// SPDX-FileCopyrightText: Copyright 2026 LBPPC
// SPDX-License-Identifier: GPL-2.0-or-later

#include "core/libraries/np/lbppc_identity.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "common/logging/log.h"
#include "common/path_util.h"
#include "core/libraries/net/net.h"
#include "core/libraries/net/net_upnp.h"
#include "core/libraries/np/np_handler/np_handler.h"
#include "core/libraries/np/np_signaling/np_signaling_state.h"
#include "core/libraries/np/np_signaling/np_signaling_transport.h"
#include "shadnet.pb.h"
#include "shadnet/client.h"

namespace Libraries::Np::LbppcIdentity {
namespace {

using Clock = std::chrono::steady_clock;
using Key32 = std::array<u8, 32>;
using Key16 = std::array<u8, 16>;

// TUS: LBPPC's own storage (not the game's), slot 1 of each account: "LBPPCpk1" then up to 4 Ed25519 public keys.
constexpr char kTusComId[13] = "LBPPCKEY0000";
constexpr s32 kTusSlot = 1;
constexpr u8 kSlotMagic[8] = {'L', 'B', 'P', 'P', 'C', 'p', 'k', '1'};
constexpr size_t kMaxPublishedKeys = 4;

// UDP: "LBPPCid2", a kind, then the fields below. Online ids are 16 bytes, zero padded; addresses and ports are
// in network order as received.
constexpr u8 kMagic[8] = {'L', 'B', 'P', 'P', 'C', 'i', 'd', '2'};
constexpr u8 kChallenge = 1; // nonce(16) from(16) to(16) addr(4) port(2)                         = 63 bytes
constexpr u8 kAnswer = 2;    // nonce(16) from(16) to(16) addr(4) port(2) eph(32) | sig(64)        = 159 bytes
constexpr u8 kKey = 3;       // iv(12) from(16) to(16) eph(32) locked(1) created(8) | ct(16) tag(16) | sig(64) = 190
constexpr size_t kChallengeSize = 63, kAnswerSigned = 95, kAnswerSize = 159;
constexpr size_t kKeyAad = 94, kKeySigned = 126, kKeySize = 190;

constexpr auto kChallengeResend = std::chrono::seconds(1);
constexpr auto kChallengeTimeout = std::chrono::seconds(10);
constexpr auto kAskInterval = std::chrono::seconds(2); // per player and address
constexpr auto kVerifiedLife = std::chrono::minutes(10);
constexpr auto kKeyResend = std::chrono::seconds(2);
constexpr size_t kMaxChallenges = 32;

struct Challenge {
    std::string online_id;
    u32 addr = 0;
    u16 port = 0;
    Clock::time_point deadline;
    Clock::time_point last_sent;
    std::vector<std::function<void(bool)>> done;
    std::vector<u8> answer; // kept until the player's keys arrive from TUS
};

struct VerifiedPeer {
    u32 addr = 0;
    u16 port = 0;
    Clock::time_point until;
    Key32 eph{};
};

struct SessionKey {
    Key16 key{};
    bool locked = false; // in use with a peer: wins over keys that are not
    u64 created = 0;     // ms since 1970: the older wins
};

struct TusRequest {
    enum class Kind { ReadOwn, WriteOwn, Fetch } kind;
    std::string online_id;
};

struct State {
    std::mutex mutex;
    std::shared_ptr<ShadNet::ShadNetClient> client;
    std::string me;
    EVP_PKEY* sign_key = nullptr;
    Key32 sign_pub{};
    EVP_PKEY* eph_key = nullptr; // X25519, one per run
    Key32 eph_pub{};
    std::map<u64, TusRequest> tus;
    std::map<std::string, std::vector<Key32>> keys; // published keys per player (fetched once per run)
    std::set<std::string> fetching;
    std::map<Key16, Challenge> challenges;
    std::map<std::string, Clock::time_point> last_ask;
    std::multimap<std::string, VerifiedPeer> verified;
    u8* slot = nullptr;
    SessionKey session;
    std::set<std::string> agreed;
    std::map<std::string, Clock::time_point> last_key_sent;
    std::function<void(const std::string&)> on_agreed;
};
State& S() {
    static State state;
    return state;
}

// ---- small helpers ---------------------------------------------------------------------------------------------

void PutId(u8* out, const std::string& id) {
    std::memset(out, 0, 16);
    std::memcpy(out, id.data(), std::min<size_t>(id.size(), 16));
}
std::string GetId(const u8* in) {
    size_t n = 0;
    while (n < 16 && in[n] != 0) {
        ++n;
    }
    return std::string(reinterpret_cast<const char*>(in), n);
}
std::string Key(const std::string& id, u32 addr, u16 port) {
    return id + '|' + std::to_string(addr) + ':' + std::to_string(port);
}
u64 NowMs() {
    return static_cast<u64>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count());
}
template <size_t N>
std::array<u8, N> RandomBytes() {
    std::array<u8, N> out{};
    RAND_bytes(out.data(), static_cast<int>(N));
    return out;
}

bool IsLocalNetworkAddr(u32 addr_nbo) {
    const u8* b = reinterpret_cast<const u8*>(&addr_nbo);
    return b[0] == 10 || b[0] == 127 || (b[0] == 172 && (b[1] & 0xf0) == 16) ||
           (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) ||
           (b[0] == 100 && (b[1] & 0xc0) == 64);
}

// Where this game is, as other players see it: the STUN reply's address and port, and the UPnP mapping.
std::vector<std::pair<u32, u16>> OwnEndpoints() {
    std::vector<std::pair<u32, u16>> out;
    const auto add = [&](u32 addr, u16 port) {
        if (addr != 0 && port != 0 &&
            std::find(out.begin(), out.end(), std::make_pair(addr, port)) == out.end()) {
            out.emplace_back(addr, port);
        }
    };
    {
        NpSignaling::SignalingMutexGuard lock;
        for (const auto& [ctx_id, ctx] : NpHandler::GetInstance().GetSignalingState().contexts) {
            if (ctx.active) {
                add(ctx.ext_addr.load(), ctx.ext_port.load());
            }
        }
    }
    auto& upnp = Net::UPnPClient::Instance();
    if (upnp.IsAvailable()) {
        add(upnp.GetExternalIp(), Net::sceNetHtons(upnp.GetExternalPort()));
    }
    return out;
}

// ---- crypto (OpenSSL) ------------------------------------------------------------------------------------------

std::array<u8, 64> Sign(EVP_PKEY* key, const u8* data, size_t size) {
    std::array<u8, 64> sig{};
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t len = sig.size();
    if (!ctx || EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) != 1 ||
        EVP_DigestSign(ctx, sig.data(), &len, data, size) != 1) {
        LOG_ERROR(Lib_NpSignaling, "identity: signing failed");
    }
    EVP_MD_CTX_free(ctx);
    return sig;
}

bool CheckSignature(const std::vector<Key32>& keys, const u8* data, size_t size, const u8* sig) {
    for (const Key32& pub : keys) {
        EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        const bool ok = key && ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key) == 1 &&
                        EVP_DigestVerify(ctx, sig, 64, data, size) == 1;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        if (ok) {
            return true;
        }
    }
    return false;
}

// The AES-128 key two players share: SHA-256 of their X25519 secret and both names, sender first.
bool PairKey(EVP_PKEY* mine, const Key32& theirs, const std::string& from, const std::string& to,
             Key16* out) {
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, theirs.data(), theirs.size());
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(mine, nullptr);
    Key32 shared{};
    size_t len = shared.size();
    const bool ok = peer && ctx && EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
                    EVP_PKEY_derive(ctx, shared.data(), &len) == 1 && len == shared.size();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    if (!ok) {
        return false;
    }
    u8 input[32 + 16 + 16];
    std::memcpy(input, shared.data(), 32);
    PutId(input + 32, from);
    PutId(input + 48, to);
    u8 digest[32];
    unsigned int dlen = 0;
    if (EVP_Digest(input, sizeof(input), digest, &dlen, EVP_sha256(), nullptr) != 1) {
        return false;
    }
    std::memcpy(out->data(), digest, 16);
    return true;
}

bool Gcm(bool encrypt, const Key16& key, const u8* iv, const u8* aad, size_t aad_size, const u8* in, u8* out,
         u8* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    bool ok = ctx && (encrypt ? EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)
                              : EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              (encrypt ? EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv)
                       : EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv)) == 1;
    if (ok && encrypt) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_size)) == 1 &&
             EVP_EncryptUpdate(ctx, out, &len, in, 16) == 1 && EVP_EncryptFinal_ex(ctx, out + len, &len) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    } else if (ok) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_size)) == 1 &&
             EVP_DecryptUpdate(ctx, out, &len, in, 16) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1 &&
             EVP_DecryptFinal_ex(ctx, out + len, &len) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// This PC's key for an account: a 32-byte Ed25519 seed in the user folder, made the first time.
EVP_PKEY* LoadSigningKey(const std::string& online_id) {
    std::string name;
    for (const char c : online_id) {
        name += std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' ? c : '_';
    }
    const auto dir = Common::FS::GetUserPath(Common::FS::PathType::UserDir) / "online_keys";
    const auto path = dir / (name + ".key");
    std::array<u8, 32> seed{};
    bool have = false;
    {
        std::ifstream in(path, std::ios::binary);
        have = in && in.read(reinterpret_cast<char*>(seed.data()), seed.size()) &&
               in.gcount() == static_cast<std::streamsize>(seed.size());
    }
    if (!have) {
        seed = RandomBytes<32>();
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(seed.data()), seed.size());
        if (!out) {
            LOG_ERROR(Lib_NpSignaling, "identity: could not save this PC's key to {}", path.string());
        } else {
            LOG_INFO(Lib_NpSignaling, "identity: made this PC's key for '{}'", online_id);
        }
    }
    return EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
}

// ---- TUS -------------------------------------------------------------------------------------------------------

std::vector<u8> TusPayload(const std::string& proto) {
    std::vector<u8> out(kTusComId, kTusComId + 12);
    const u32 size = static_cast<u32>(proto.size());
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<u8>(size >> (8 * i)));
    }
    out.insert(out.end(), proto.begin(), proto.end());
    return out;
}

std::vector<Key32> ParseSlot(const std::string& data) {
    std::vector<Key32> keys;
    if (data.size() < sizeof(kSlotMagic) || std::memcmp(data.data(), kSlotMagic, sizeof(kSlotMagic)) != 0) {
        return keys;
    }
    for (size_t at = sizeof(kSlotMagic); at + 32 <= data.size() && keys.size() < kMaxPublishedKeys; at += 32) {
        Key32 k{};
        std::memcpy(k.data(), data.data() + at, 32);
        keys.push_back(k);
    }
    return keys;
}

// Locked: sends a TUS read of online_id's slot ("" = ours).
void SendTusReadLocked(State& s, const std::string& online_id, TusRequest::Kind kind) {
    if (!s.client) {
        return;
    }
    shadnet::TusGetDataRequest req;
    if (!online_id.empty()) {
        req.set_ownernpid(online_id);
    }
    req.set_slotid(kTusSlot);
    const u64 pkt = s.client->SubmitRequest(ShadNet::CommandType::TusGetData, TusPayload(req.SerializeAsString()));
    s.tus[pkt] = {kind, online_id};
}

void FetchKeysLocked(State& s, const std::string& online_id) {
    if (s.keys.count(online_id) || !s.fetching.insert(online_id).second) {
        return;
    }
    SendTusReadLocked(s, online_id, TusRequest::Kind::Fetch);
}

// ---- verification ----------------------------------------------------------------------------------------------

struct Done {
    std::vector<std::function<void(bool)>> callbacks;
    bool ok = false;
    std::string online_id;
};

// Locked: checks a kept answer against the player's published keys; fills done when it is decided.
bool CheckAnswerLocked(State& s, const Key16& nonce, Challenge& c, Done* done) {
    const auto keys = s.keys.find(c.online_id);
    if (keys == s.keys.end() || c.answer.size() != kAnswerSize) {
        return false; // waiting for the keys
    }
    const bool ok = CheckSignature(keys->second, c.answer.data(), kAnswerSigned, c.answer.data() + kAnswerSigned);
    if (ok) {
        VerifiedPeer peer;
        peer.addr = c.addr;
        peer.port = c.port;
        peer.until = Clock::now() + kVerifiedLife;
        std::memcpy(peer.eph.data(), c.answer.data() + 63, 32);
        auto [it, end] = s.verified.equal_range(c.online_id);
        for (; it != end; ++it) {
            if (it->second.addr == c.addr && it->second.port == c.port) {
                break;
            }
        }
        if (it != end) {
            it->second = peer;
        } else {
            s.verified.insert({c.online_id, peer});
        }
        LOG_INFO(Lib_NpSignaling, "identity: '{}' proved it is at {:#x}:{}", c.online_id, c.addr,
                 Net::sceNetNtohs(c.port));
    } else {
        LOG_WARNING(Lib_NpSignaling, "identity: an answer for '{}' from {:#x}:{} has no valid signature",
                    c.online_id, c.addr, Net::sceNetNtohs(c.port));
        std::printf("Online: refused a connection named %s (it could not prove it is that player)\n",
                    c.online_id.c_str());
    }
    done->callbacks = std::move(c.done);
    done->ok = ok;
    done->online_id = c.online_id;
    s.challenges.erase(nonce);
    return true;
}

void RunDone(std::vector<Done>& done) {
    for (auto& d : done) {
        for (auto& cb : d.callbacks) {
            if (cb) {
                cb(d.ok);
            }
        }
    }
}

void HandleChallenge(const u8* p, u32 addr, u16 port) {
    std::vector<u8> answer(kAnswerSize);
    {
        State& s = S();
        std::scoped_lock lock{s.mutex};
        if (!s.sign_key || !s.eph_key || GetId(p + 41) != s.me) {
            return;
        }
    }
    // The address the asker wrote to must be ours, so that an answer relayed by someone else proves nothing.
    u32 target_addr = 0;
    u16 target_port = 0;
    std::memcpy(&target_addr, p + 57, 4);
    std::memcpy(&target_port, p + 61, 2);
    bool ours = IsLocalNetworkAddr(target_addr);
    for (const auto& [a, pt] : OwnEndpoints()) {
        ours = ours || (a == target_addr && pt == target_port);
    }
    if (!ours) {
        LOG_WARNING(Lib_NpSignaling, "identity: '{}' asked us to prove an address that is not ours ({:#x}:{})",
                    GetId(p + 25), target_addr, Net::sceNetNtohs(target_port));
        return;
    }
    State& s = S();
    std::scoped_lock lock{s.mutex};
    std::memcpy(answer.data(), kMagic, 8);
    answer[8] = kAnswer;
    std::memcpy(answer.data() + 9, p + 9, 16); // nonce
    PutId(answer.data() + 25, s.me);
    std::memcpy(answer.data() + 41, p + 25, 16); // the asker
    std::memcpy(answer.data() + 57, p + 57, 6);  // the address asked about
    std::memcpy(answer.data() + 63, s.eph_pub.data(), 32);
    const auto sig = Sign(s.sign_key, answer.data(), kAnswerSigned);
    std::memcpy(answer.data() + kAnswerSigned, sig.data(), 64);
    NpSignaling::Transport::ControlSendTo(answer.data(), static_cast<u32>(answer.size()), addr, port);
}

void HandleAnswer(const u8* p, u32 addr, u16 port) {
    std::vector<Done> done;
    {
        State& s = S();
        std::scoped_lock lock{s.mutex};
        Key16 nonce{};
        std::memcpy(nonce.data(), p + 9, 16);
        const auto it = s.challenges.find(nonce);
        if (it == s.challenges.end()) {
            return;
        }
        Challenge& c = it->second;
        u32 target_addr = 0;
        u16 target_port = 0;
        std::memcpy(&target_addr, p + 57, 4);
        std::memcpy(&target_port, p + 61, 2);
        // From the address asked about, about that address, by that player, to us.
        if (addr != c.addr || port != c.port || target_addr != c.addr || target_port != c.port ||
            GetId(p + 25) != c.online_id || GetId(p + 41) != s.me) {
            return;
        }
        c.answer.assign(p, p + kAnswerSize);
        Done d;
        if (CheckAnswerLocked(s, nonce, c, &d)) {
            done.push_back(std::move(d));
        } else {
            FetchKeysLocked(s, c.online_id);
        }
    }
    RunDone(done);
}

// ---- session key -----------------------------------------------------------------------------------------------

bool Better(const SessionKey& a, const SessionKey& b) {
    if (a.locked != b.locked) {
        return a.locked;
    }
    if (a.created != b.created) {
        return a.created < b.created;
    }
    return a.key < b.key;
}

void WriteSlotLocked(State& s) {
    if (s.slot) {
        std::memcpy(s.slot, s.session.key.data(), 16);
    }
}

void NewSessionKeyLocked(State& s) {
    s.session.key = RandomBytes<16>();
    s.session.locked = false;
    s.session.created = NowMs();
    s.agreed.clear();
    s.last_key_sent.clear();
    WriteSlotLocked(s);
}

const VerifiedPeer* FindVerifiedLocked(State& s, const std::string& id, u32 addr, u16 port) {
    auto [it, end] = s.verified.equal_range(id);
    const auto now = Clock::now();
    for (; it != end; ++it) {
        if (it->second.addr == addr && it->second.port == port && now < it->second.until) {
            it->second.until = now + kVerifiedLife;
            return &it->second;
        }
    }
    return nullptr;
}

void SendKeyLocked(State& s, const std::string& to, const VerifiedPeer& peer) {
    Key16 pair{};
    if (!s.eph_key || !s.sign_key || !PairKey(s.eph_key, peer.eph, s.me, to, &pair)) {
        return;
    }
    std::array<u8, kKeySize> msg{};
    std::memcpy(msg.data(), kMagic, 8);
    msg[8] = kKey;
    const auto iv = RandomBytes<12>();
    std::memcpy(msg.data() + 9, iv.data(), 12);
    PutId(msg.data() + 21, s.me);
    PutId(msg.data() + 37, to);
    std::memcpy(msg.data() + 53, s.eph_pub.data(), 32);
    msg[85] = s.session.locked ? 1 : 0;
    std::memcpy(msg.data() + 86, &s.session.created, 8);
    if (!Gcm(true, pair, iv.data(), msg.data(), kKeyAad, s.session.key.data(), msg.data() + 94,
             msg.data() + 110)) {
        return;
    }
    const auto sig = Sign(s.sign_key, msg.data(), kKeySigned);
    std::memcpy(msg.data() + kKeySigned, sig.data(), 64);
    NpSignaling::Transport::ControlSendTo(msg.data(), static_cast<u32>(msg.size()), peer.addr, peer.port);
}

void HandleKey(const u8* p, u32 addr, u16 port) {
    std::string agreed_with;
    std::function<void(const std::string&)> on_agreed;
    {
        State& s = S();
        std::scoped_lock lock{s.mutex};
        const std::string from = GetId(p + 21);
        if (!s.slot || !s.eph_key || GetId(p + 37) != s.me) {
            return;
        }
        // Only from where that player proved to be, signed by one of its keys.
        const VerifiedPeer* peer = FindVerifiedLocked(s, from, addr, port);
        if (!peer) {
            return;
        }
        const auto keys = s.keys.find(from);
        if (keys == s.keys.end() || !CheckSignature(keys->second, p, kKeySigned, p + kKeySigned)) {
            LOG_WARNING(Lib_NpSignaling, "identity: a session key from '{}' has no valid signature", from);
            return;
        }
        Key32 their_eph{};
        std::memcpy(their_eph.data(), p + 53, 32);
        Key16 pair{};
        SessionKey theirs;
        u8 tag[16];
        std::memcpy(tag, p + 110, 16);
        if (!PairKey(s.eph_key, their_eph, from, s.me, &pair) ||
            !Gcm(false, pair, p + 9, p, kKeyAad, p + 94, theirs.key.data(), tag)) {
            return; // an old message (another run's key) or damaged
        }
        theirs.locked = p[85] != 0;
        std::memcpy(&theirs.created, p + 86, 8);
        const bool was_agreed = s.agreed.count(from) != 0;
        if (theirs.key == s.session.key) {
            s.agreed.insert(from);
        } else if (Better(theirs, s.session)) {
            s.session = theirs;
            s.agreed.clear();
            s.last_key_sent.clear();
            s.agreed.insert(from);
            WriteSlotLocked(s);
            LOG_INFO(Lib_NpSignaling, "identity: now using '{}''s session key", from);
        } else {
            s.agreed.erase(from);
            s.last_key_sent.erase(from); // send ours now
        }
        if (s.agreed.count(from)) {
            s.session.locked = true;
            if (!was_agreed) {
                agreed_with = from;
                on_agreed = s.on_agreed;
                // Tell the sender once that we now use the same key (it stops offering it then).
                SendKeyLocked(s, from, *peer);
            }
        }
    }
    if (!agreed_with.empty() && on_agreed) {
        on_agreed(agreed_with);
    }
}

} // namespace

// ---- public ----------------------------------------------------------------------------------------------------

void OnSignedIn(std::shared_ptr<ShadNet::ShadNetClient> client) {
    if (!client) {
        return;
    }
    State& s = S();
    std::scoped_lock lock{s.mutex};
    s.client = client;
    s.me = client->GetNpid();
    EVP_PKEY_free(s.sign_key);
    s.sign_key = LoadSigningKey(s.me);
    size_t len = s.sign_pub.size();
    if (!s.sign_key || EVP_PKEY_get_raw_public_key(s.sign_key, s.sign_pub.data(), &len) != 1) {
        LOG_ERROR(Lib_NpSignaling, "identity: no key for '{}'; other players will refuse us", s.me);
        EVP_PKEY_free(s.sign_key);
        s.sign_key = nullptr;
        return;
    }
    if (!s.eph_key) {
        const auto seed = RandomBytes<32>();
        s.eph_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, seed.data(), seed.size());
        len = s.eph_pub.size();
        if (!s.eph_key || EVP_PKEY_get_raw_public_key(s.eph_key, s.eph_pub.data(), &len) != 1) {
            LOG_ERROR(Lib_NpSignaling, "identity: no X25519 key; no session keys this run");
            EVP_PKEY_free(s.eph_key);
            s.eph_key = nullptr;
        }
    }
    SendTusReadLocked(s, "", TusRequest::Kind::ReadOwn);
}

bool OnAsyncReply(ShadNet::CommandType cmd, u64 pkt_id, ShadNet::ErrorType error, const std::vector<u8>& body) {
    if (cmd != ShadNet::CommandType::TusGetData && cmd != ShadNet::CommandType::TusSetData) {
        return false;
    }
    std::vector<Done> done;
    {
        State& s = S();
        std::scoped_lock lock{s.mutex};
        const auto it = s.tus.find(pkt_id);
        if (it == s.tus.end()) {
            return false;
        }
        const TusRequest req = it->second;
        s.tus.erase(it);

        std::string data;
        if (cmd == ShadNet::CommandType::TusGetData && error == ShadNet::ErrorType::NoError && body.size() >= 4) {
            const u32 size = body[0] | (body[1] << 8) | (body[2] << 16) | (static_cast<u32>(body[3]) << 24);
            shadnet::TusGetDataResponse resp;
            if (4 + static_cast<size_t>(size) <= body.size() && resp.ParseFromArray(body.data() + 4, size) &&
                resp.status().set()) {
                data = resp.data();
            }
        }

        switch (req.kind) {
        case TusRequest::Kind::ReadOwn: {
            // Our key first, then the other PCs' (the oldest drops out past kMaxPublishedKeys).
            const auto published = ParseSlot(data);
            if (std::find(published.begin(), published.end(), s.sign_pub) != published.end()) {
                LOG_INFO(Lib_NpSignaling, "identity: this PC's key is published");
                break;
            }
            std::string slot(reinterpret_cast<const char*>(kSlotMagic), sizeof(kSlotMagic));
            slot.append(reinterpret_cast<const char*>(s.sign_pub.data()), 32);
            for (size_t i = 0; i < published.size() && i + 1 < kMaxPublishedKeys; ++i) {
                slot.append(reinterpret_cast<const char*>(published[i].data()), 32);
            }
            shadnet::TusSetDataRequest set;
            set.set_slotid(kTusSlot);
            set.set_data(slot);
            if (s.client) {
                const u64 pkt =
                    s.client->SubmitRequest(ShadNet::CommandType::TusSetData, TusPayload(set.SerializeAsString()));
                s.tus[pkt] = {TusRequest::Kind::WriteOwn, ""};
            }
            break;
        }
        case TusRequest::Kind::WriteOwn:
            if (error == ShadNet::ErrorType::NoError) {
                LOG_INFO(Lib_NpSignaling, "identity: published this PC's key");
            } else {
                LOG_ERROR(Lib_NpSignaling, "identity: could not publish this PC's key (error {}); other players "
                                           "will refuse us",
                          static_cast<int>(error));
            }
            break;
        case TusRequest::Kind::Fetch: {
            s.fetching.erase(req.online_id);
            if (error != ShadNet::ErrorType::NoError) {
                LOG_WARNING(Lib_NpSignaling, "identity: could not read '{}''s keys (error {})", req.online_id,
                            static_cast<int>(error));
            }
            s.keys[req.online_id] = ParseSlot(data);
            if (s.keys[req.online_id].empty()) {
                LOG_WARNING(Lib_NpSignaling, "identity: '{}' has published no key (an older LBPPC?)",
                            req.online_id);
            }
            std::vector<Key16> waiting;
            for (auto& [nonce, c] : s.challenges) {
                if (c.online_id == req.online_id && !c.answer.empty()) {
                    waiting.push_back(nonce);
                }
            }
            for (const Key16& nonce : waiting) {
                Done d;
                if (CheckAnswerLocked(s, nonce, s.challenges[nonce], &d)) {
                    done.push_back(std::move(d));
                }
            }
            break;
        }
        }
    }
    RunDone(done);
    return true;
}

bool HandlePacket(const u8* data, size_t size, u32 addr, u16 port) {
    if (size < 9 || std::memcmp(data, kMagic, 8) != 0) {
        return false;
    }
    switch (data[8]) {
    case kChallenge:
        if (size == kChallengeSize) {
            HandleChallenge(data, addr, port);
        }
        break;
    case kAnswer:
        if (size == kAnswerSize) {
            HandleAnswer(data, addr, port);
        }
        break;
    case kKey:
        if (size == kKeySize) {
            HandleKey(data, addr, port);
        }
        break;
    default:
        break;
    }
    return true;
}

bool Verified(const std::string& online_id, u32 addr, u16 port) {
    State& s = S();
    std::scoped_lock lock{s.mutex};
    return FindVerifiedLocked(s, online_id, addr, port) != nullptr;
}

void Verify(const std::string& online_id, u32 addr, u16 port, std::function<void(bool)> done) {
    bool already = false;
    {
        State& s = S();
        std::scoped_lock lock{s.mutex};
        if (FindVerifiedLocked(s, online_id, addr, port)) {
            already = true;
        } else {
            for (auto& [nonce, c] : s.challenges) {
                if (c.online_id == online_id && c.addr == addr && c.port == port) {
                    c.done.push_back(std::move(done));
                    return;
                }
            }
            const auto now = Clock::now();
            auto& last = s.last_ask[Key(online_id, addr, port)];
            if (s.challenges.size() >= kMaxChallenges || now - last < kAskInterval) {
                return;
            }
            last = now;
            Challenge c;
            c.online_id = online_id;
            c.addr = addr;
            c.port = port;
            c.deadline = now + kChallengeTimeout;
            c.done.push_back(std::move(done));
            s.challenges.emplace(RandomBytes<16>(), std::move(c)); // sent by Step
            FetchKeysLocked(s, online_id);
        }
    }
    if (already && done) {
        done(true);
    }
}

void SetKeySlot(u8* slot) {
    State& s = S();
    std::scoped_lock lock{s.mutex};
    s.slot = slot;
    NewSessionKeyLocked(s);
    LOG_INFO(Lib_NpSignaling, "identity: P2P packets use a session key, never the game's own");
}

bool KeyInstalled() {
    State& s = S();
    std::scoped_lock lock{s.mutex};
    return s.slot != nullptr;
}

bool KeyAgreed(const std::string& online_id) {
    State& s = S();
    std::scoped_lock lock{s.mutex};
    return s.slot == nullptr || s.agreed.count(online_id) != 0;
}

void SetOnKeyAgreed(std::function<void(const std::string&)> callback) {
    State& s = S();
    std::scoped_lock lock{s.mutex};
    s.on_agreed = std::move(callback);
}

void Step(const std::vector<Peer>& peers) {
    for (const Peer& p : peers) {
        if (p.addr != 0 && p.port != 0 && !Verified(p.online_id, p.addr, p.port)) {
            Verify(p.online_id, p.addr, p.port, nullptr);
        }
    }
    std::vector<Done> done;
    {
        State& s = S();
        std::scoped_lock lock{s.mutex};
        const auto now = Clock::now();
        // Challenges: send, resend, give up.
        for (auto it = s.challenges.begin(); it != s.challenges.end();) {
            Challenge& c = it->second;
            if (now > c.deadline) {
                LOG_WARNING(Lib_NpSignaling, "identity: no proof from '{}' at {:#x}:{}", c.online_id, c.addr,
                            Net::sceNetNtohs(c.port));
                std::printf("Online: refused a connection named %s (no proof it is that player; an older "
                            "LBPPC?)\n",
                            c.online_id.c_str());
                done.push_back({std::move(c.done), false, c.online_id});
                it = s.challenges.erase(it);
                continue;
            }
            if (c.answer.empty() && !s.me.empty() && now - c.last_sent >= kChallengeResend) {
                c.last_sent = now;
                std::array<u8, kChallengeSize> msg{};
                std::memcpy(msg.data(), kMagic, 8);
                msg[8] = kChallenge;
                std::memcpy(msg.data() + 9, it->first.data(), 16);
                PutId(msg.data() + 25, s.me);
                PutId(msg.data() + 41, c.online_id);
                std::memcpy(msg.data() + 57, &c.addr, 4);
                std::memcpy(msg.data() + 61, &c.port, 2);
                NpSignaling::Transport::ControlSendTo(msg.data(), static_cast<u32>(msg.size()), c.addr, c.port);
            }
            ++it;
        }
        // Session key: offer ours to every verified peer that does not use it yet.
        if (s.slot) {
            for (const Peer& p : peers) {
                if (s.agreed.count(p.online_id)) {
                    continue;
                }
                const VerifiedPeer* peer = FindVerifiedLocked(s, p.online_id, p.addr, p.port);
                auto& last = s.last_key_sent[p.online_id];
                if (peer && now - last >= kKeyResend) {
                    last = now;
                    SendKeyLocked(s, p.online_id, *peer);
                }
            }
            // Nobody left: the next session starts from a fresh key of our own.
            if (peers.empty() && s.session.locked) {
                NewSessionKeyLocked(s);
                LOG_INFO(Lib_NpSignaling, "identity: no peers left; a fresh session key");
            }
        }
    }
    RunDone(done);
}

} // namespace Libraries::Np::LbppcIdentity
