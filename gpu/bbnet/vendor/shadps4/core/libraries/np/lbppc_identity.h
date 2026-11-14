// SPDX-FileCopyrightText: Copyright 2026 LBPPC
// SPDX-License-Identifier: GPL-2.0-or-later

// lbppc: who a player is, and the key the game's P2P packets use, without trusting anything a packet or shadNet's
// address table says about its sender. LBP3 makes its connections with NpSignaling alone (no matching2 rooms), so
// nothing the server relays between two players is signed by it; what the server does guarantee is that only an
// account itself can write its own TUS slots. Each account keeps an Ed25519 key per PC and publishes the public
// part in a TUS slot of LBPPC's own (comId LBPPCKEY0000, slot 1, up to 4 keys: one per PC). A player is taken to
// be at an address only after answering, from there, a challenge with a signature by one of those keys. Verified
// players then agree on one session key for the game's P2P cipher, sent signed and encrypted (X25519 + AES-GCM).

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "common/types.h"

namespace ShadNet {
class ShadNetClient;
enum class CommandType : u16;
enum class ErrorType : u8;
} // namespace ShadNet

namespace Libraries::Np::LbppcIdentity {

// After a successful shadNet sign-in: loads (or makes) this PC's key and publishes it.
void OnSignedIn(std::shared_ptr<ShadNet::ShadNetClient> client);
// A shadNet reply; true when it answered one of our TUS requests.
bool OnAsyncReply(ShadNet::CommandType cmd, u64 pkt_id, ShadNet::ErrorType error,
                  const std::vector<u8>& body);
// A UDP packet on the signaling sockets; true when it was ours (addr/port network order).
bool HandlePacket(const u8* data, size_t size, u32 addr, u16 port);

// Whether online_id proved it is at addr:port (each answer extends it while in use).
bool Verified(const std::string& online_id, u32 addr, u16 port);
// Asks online_id to prove it is at addr:port; done(true) once it has. Repeated asks for the same player and
// address within a short while are dropped (done is not called for them).
void Verify(const std::string& online_id, u32 addr, u16 port, std::function<void(bool)> done);

// The 16 bytes the game's P2P cipher reads its key from (probe.c). From then on it holds a session key.
void SetKeySlot(u8* slot);
bool KeyInstalled();
// Whether online_id uses the same session key as we do (connections are reported active only then).
bool KeyAgreed(const std::string& online_id);
// Called once a player starts using our key, to report its connection again.
void SetOnKeyAgreed(std::function<void(const std::string& online_id)> callback);

struct Peer {
    std::string online_id;
    u32 addr = 0;
    u16 port = 0;
};
// Signaling thread, often: resends challenges and keys, verifies the peers we have connections with, and starts a
// fresh key once nobody is connected.
void Step(const std::vector<Peer>& peers);

} // namespace Libraries::Np::LbppcIdentity
