/* lbppc: the game in an AppContainer (Windows; on unless LBPPC_APPCONTAINER=0; docs/appcontainer-broker.md).
 *
 * runtime_sandbox.c keeps the game from starting programs and from writing outside its folders, but it can still read
 * everything the user can. An AppContainer reads only what it is given. This process (started by run.py as always)
 * gives the container "LBPPC.Game" the folders the game needs, starts the same command line inside it and waits,
 * then exits with the game's exit code (the in-game "Apply and restart", 75, still reaches run.py). It never runs game
 * code. Called first thing from runtime_memory_reserve, before the PS4 range is reserved.
 *
 * Controllers (HID) and the overlay's GPU usage (performance counters) can't be read inside: this process reads them
 * and hands them in (runtime_broker.c).
 *
 * On by default; LBPPC_APPCONTAINER=0 (the launcher's Debug page, "Game isolation") turns it off. When something is
 * missing (a server on this PC, which an AppContainer can't reach; a profile or a permission that can't be made) the
 * game does not start: it would otherwise run able to read all of the user's files, and only the log would say so.
 * It ends with CONTAINER_EXIT_CODE and a "STOP: Game isolation" line saying why; the launcher shows that line and
 * how to play without isolation (run.py passes the code on). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

#ifndef _WIN32
void runtime_container_start(void) {}
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <psapi.h>
#include <shellapi.h>
#include <wchar.h>

#define CONTAINER_NAME L"LBPPC.Game"
#define CONTAINER_EXIT_CODE 22 /* run.py CONTAINER_EXIT_CODE, the launcher's finished() */
#define READ_ACCESS (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
#define WRITE_ACCESS (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_GENERIC_WRITE | DELETE)
/* The user folder itself: its attributes and the names in it, not its files' contents. */
#define USER_FOLDER_ACCESS (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE | READ_CONTROL)

static PSID container;
static int grant_failures;
/* The game runs without the container this time: what earlier runs gave it is taken back instead (take_back). */
static int taking_back, taken_back;
static void revoke_w(const wchar_t *path, int any);

/* Every place given to the container this run (full paths), kept in <user>\container-grants.txt for the next one:
 * a place no longer given (another game folder, a DLL folder that came and went) is taken back from that record. */
static wchar_t **granted;
static int granted_count, granted_capacity;
static wchar_t record_path[MAX_PATH];

static void note_granted(const wchar_t *path) {
    wchar_t full[MAX_PATH];
    if (!GetFullPathNameW(path, MAX_PATH, full, NULL)) return;
    for (int i = 0; i < granted_count; ++i)
        if (!_wcsicmp(granted[i], full)) return;
    if (granted_count == granted_capacity) {
        const int capacity = granted_capacity ? granted_capacity * 2 : 64;
        wchar_t **more = realloc(granted, (size_t)capacity * sizeof(*more));
        if (!more) return;
        granted = more;
        granted_capacity = capacity;
    }
    wchar_t *copy = _wcsdup(full);
    if (copy) granted[granted_count++] = copy;
}

/* The record of an earlier run: each path, one per line (UTF-8), passed to seen. */
static void read_record(void (*seen)(const wchar_t *path)) {
    if (!*record_path) return;
    FILE *f = _wfopen(record_path, L"rb");
    if (!f) return;
    char line[MAX_PATH * 3];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        wchar_t wide[MAX_PATH];
        if (*line && MultiByteToWideChar(CP_UTF8, 0, line, -1, wide, MAX_PATH)) seen(wide);
    }
    fclose(f);
}

/* A recorded place not given this run: taken back. */
static void revoke_stale(const wchar_t *path) {
    for (int i = 0; i < granted_count; ++i)
        if (!_wcsicmp(granted[i], path)) return;
    revoke_w(path, 1);
}
static void revoke_recorded(const wchar_t *path) { revoke_w(path, 1); }

static void write_record(void) {
    if (!*record_path) return;
    FILE *f = _wfopen(record_path, L"wb");
    if (!f) {
        fwprintf(stderr, L"Container: %ls could not be written; places given now may stay given\n", record_path);
        return;
    }
    for (int i = 0; i < granted_count; ++i) {
        char line[MAX_PATH * 3];
        if (WideCharToMultiByte(CP_UTF8, 0, granted[i], -1, line, sizeof(line), NULL, NULL)) fprintf(f, "%s\n", line);
    }
    fclose(f);
}

/* Whether the DACL already gives the container mask (inherited by what a folder holds, for a folder). */
static int has_grant(PACL dacl, DWORD mask, int dir) {
    if (!dacl) return 0;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER *ace;
        if (!GetAce(dacl, i, (void **)&ace) || ace->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        ACCESS_ALLOWED_ACE *allowed = (ACCESS_ALLOWED_ACE *)ace;
        const BYTE inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        if (EqualSid((PSID)&allowed->SidStart, container) && (allowed->Mask & mask) == mask &&
            !(ace->AceFlags & INHERIT_ONLY_ACE) && (!dir || (ace->AceFlags & inherit) == inherit))
            return 1;
    }
    return 0;
}

/* One allow entry for the container, inherited by a folder's contents; nothing when it is there already. */
static void grant_w(const wchar_t *path, DWORD mask, int dir) {
    if (taking_back) {
        revoke_w(path, 1);
        return;
    }
    PACL dacl = NULL, updated = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD error = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    if (error == ERROR_SUCCESS && !has_grant(dacl, mask, dir)) {
        EXPLICIT_ACCESS_W access = {0};
        access.grfAccessPermissions = mask;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = dir ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = (LPWSTR)container;
        error = SetEntriesInAclW(1, &access, dacl, &updated);
        if (error == ERROR_SUCCESS)
            error = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, updated,
                                          NULL);
    }
    if (error != ERROR_SUCCESS) {
        fwprintf(stderr, L"Container: %ls could not be given to the game (error %lu)\n", path, error);
        ++grant_failures;
    } else {
        note_granted(path);
    }
    if (updated) LocalFree(updated);
    if (sd) LocalFree(sd);
}

/* runtime_sandbox_prepare's folders and files: to read, or to read and write. */
static void grant_prepared(const char *path, int dir, int writable) {
    wchar_t wide[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, path, -1, wide, MAX_PATH))
        grant_w(wide, writable ? WRITE_ACCESS : READ_ACCESS, dir);
}

/* Takes back what this container was given on path itself (what it holds, through inheritance, goes with it): any
 * grant, or (any=0) only one its contents inherit (the whole folder, as earlier versions gave it). */
static void revoke_w(const wchar_t *path, int any) {
    PACL dacl = NULL, updated = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd) !=
        ERROR_SUCCESS)
        return;
    int explicit_grant = 0;
    for (DWORD i = 0; dacl && i < dacl->AceCount; ++i) {
        ACE_HEADER *ace;
        if (GetAce(dacl, i, (void **)&ace) && ace->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            !(ace->AceFlags & INHERITED_ACE) && (any || (ace->AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE))) &&
            EqualSid((PSID) & ((ACCESS_ALLOWED_ACE *)ace)->SidStart, container))
            explicit_grant = 1;
    }
    if (explicit_grant) {
        EXPLICIT_ACCESS_W access = {0};
        access.grfAccessMode = REVOKE_ACCESS;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        access.Trustee.ptstrName = (LPWSTR)container;
        if (SetEntriesInAclW(1, &access, dacl, &updated) == ERROR_SUCCESS &&
            SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, updated,
                                  NULL) == ERROR_SUCCESS)
            ++taken_back;
    }
    if (updated) LocalFree(updated);
    if (sd) LocalFree(sd);
}

/* The folder a file is in (or the folder itself), given to read. */
static void grant_read(const wchar_t *path) {
    const DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) return;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        grant_w(path, READ_ACCESS, 1);
        return;
    }
    wchar_t folder[MAX_PATH];
    wcsncpy(folder, path, MAX_PATH - 1);
    folder[MAX_PATH - 1] = 0;
    wchar_t *slash = wcsrchr(folder, L'\\');
    wchar_t *other = wcsrchr(folder, L'/');
    if (other > slash) slash = other;
    if (slash) {
        *slash = 0;
        grant_w(folder, READ_ACCESS, 1);
    }
}

static int starts_with_folder(const wchar_t *path, const wchar_t *folder) {
    const size_t n = wcslen(folder);
    return n && !_wcsnicmp(path, folder, n) && (path[n] == L'\\' || path[n] == L'/');
}

/* The folders of the DLLs this process has loaded (the game loads the same ones), except Windows' own. */
static void grant_module_folders(void) {
    wchar_t windows[MAX_PATH] = L"";
    GetWindowsDirectoryW(windows, MAX_PATH);
    HMODULE modules[512];
    DWORD needed = 0;
    if (!K32EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) return;
    for (DWORD i = 0; i < needed / sizeof(HMODULE) && i < 512; ++i) {
        wchar_t path[MAX_PATH];
        if (!GetModuleFileNameW(modules[i], path, MAX_PATH) || starts_with_folder(path, windows)) continue;
        grant_read(path);
    }
}

/* An address of this PC: loopback, unspecified, or one of its own (an AppContainer reaches none of them). */
static int local_address(const struct sockaddr *address, const struct addrinfo *own) {
    if (address->sa_family == AF_INET) {
        const struct in_addr a = ((const struct sockaddr_in *)address)->sin_addr;
        if (a.S_un.S_un_b.s_b1 == 127 || a.S_un.S_addr == 0) return 1;
    } else if (address->sa_family == AF_INET6) {
        const struct in6_addr *a = &((const struct sockaddr_in6 *)address)->sin6_addr;
        static const struct in6_addr any;
        if (IN6_IS_ADDR_LOOPBACK(a) || !memcmp(a, &any, sizeof(any))) return 1;
        if (IN6_IS_ADDR_V4MAPPED(a) && a->s6_addr[12] == 127) return 1;
    } else {
        return 0;
    }
    for (const struct addrinfo *o = own; o; o = o->ai_next) {
        if (o->ai_family != address->sa_family) continue;
        if (address->sa_family == AF_INET &&
            ((const struct sockaddr_in *)o->ai_addr)->sin_addr.S_un.S_addr ==
                ((const struct sockaddr_in *)address)->sin_addr.S_un.S_addr)
            return 1;
        if (address->sa_family == AF_INET6 && !memcmp(&((const struct sockaddr_in6 *)o->ai_addr)->sin6_addr,
                                                      &((const struct sockaddr_in6 *)address)->sin6_addr,
                                                      sizeof(struct in6_addr)))
            return 1;
    }
    return 0;
}

/* Whether a server setting (a URL, host:port, [v6]:port or a bare host) names this PC. */
static int local_server(const char *value) {
    if (!value || !*value) return 0;
    const char *host = strstr(value, "://");
    host = host ? host + 3 : value;
    const char *at = strpbrk(host, "@/");
    if (at && *at == '@') host = at + 1;
    char name[256];
    size_t n;
    if (*host == '[') {
        ++host;
        n = strcspn(host, "]");
    } else {
        n = strcspn(host, ":/?#");
        const char *colon = strchr(host, ':');
        if (colon && strchr(colon + 1, ':')) n = strcspn(host, "/?#"); /* a bare IPv6 address */
    }
    if (!n || n >= sizeof(name)) return 0;
    memcpy(name, host, n);
    name[n] = 0;
    const size_t length = strlen(name);
    if (!_stricmp(name, "localhost") || (length > 10 && !_stricmp(name + length - 10, ".localhost"))) return 1;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) return 0;
    int local = 0;
    char own_name[256] = "";
    struct addrinfo hints, *found = NULL, *own = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (!gethostname(own_name, sizeof(own_name))) {
        if (!_stricmp(name, own_name)) local = 1;
        getaddrinfo(own_name, NULL, &hints, &own); /* this PC's own addresses */
    }
    if (!local && !getaddrinfo(name, NULL, &hints, &found))
        for (const struct addrinfo *a = found; a && !local; a = a->ai_next) local = local_address(a->ai_addr, own);
    if (found) freeaddrinfo(found);
    if (own) freeaddrinfo(own);
    WSACleanup();
    return local;
}

/* What it reads: the program and its DLLs, and every file or folder named on the command line (the prepared game in
 * out/, the game, its update). Not the whole user folder, which holds the launcher's settings: its folders and files
 * one by one, to read or to write, as runtime_sandbox_prepare lists them. With taking_back, the same walk takes it
 * all back. */
static void give_folders(void) {
    grant_module_folders();
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const char *user = "user";
    static char user_narrow[MAX_PATH];
    for (int i = 1; argv && i < argc; ++i) {
        if (!wcscmp(argv[i], L"--user") && i + 1 < argc) {
            if (WideCharToMultiByte(CP_ACP, 0, argv[i + 1], -1, user_narrow, sizeof(user_narrow), NULL, NULL))
                user = user_narrow;
            revoke_w(argv[i + 1], 0); /* given whole by earlier versions */
            /* The folder itself, not what it holds: its attributes and names (shadPS4 checks it exists). */
            grant_w(argv[i + 1], USER_FOLDER_ACCESS, 0);
            ++i;
            continue;
        }
        grant_read(argv[i]);
    }
    if (argv) LocalFree(argv);
    wchar_t user_wide[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, user, -1, user_wide, MAX_PATH))
        _snwprintf(record_path, MAX_PATH, L"%ls\\container-grants.txt", user_wide);
    revoke_w(L"user", 0);
    grant_w(L"user", USER_FOLDER_ACCESS, 0);
    if (!runtime_sandbox_prepare(user, grant_prepared)) ++grant_failures;
}

/* The game runs outside the container, sandboxed at low integrity (runtime_sandbox.c). Windows keeps a low-integrity
 * process away from anything whose permissions name a particular AppContainer (that container's data, not a low
 * process's), even what it could read before (the game, its saves, lbppc.ini): what earlier runs gave LBPPC.Game is
 * taken back. Next to nothing to do when it was taken back already; given again when isolation is back on. */
static void take_back(void) {
    if (!container && FAILED(DeriveAppContainerSidFromAppContainerName(CONTAINER_NAME, &container))) return;
    const ULONGLONG started = GetTickCount64();
    taking_back = 1;
    give_folders();
    taking_back = 0;
    read_record(revoke_recorded); /* also what earlier runs gave that this run's walk doesn't name */
    if (*record_path) _wremove(record_path);
    if (taken_back)
        printf("Container: what earlier runs gave AppContainer LBPPC.Game taken back (%d places, %llu ms)\n",
               taken_back, (unsigned long long)(GetTickCount64() - started));
}

/* The game does not start. What was given so far stays given (the next run uses it) and is recorded with what
   earlier runs gave, so that turning isolation off takes all of it back. */
static void give_up(const char *why) {
    if (granted_count) {
        read_record(note_granted);
        write_record();
    }
    fprintf(stderr, "STOP: Game isolation could not start: %s. The game does not start without it; the launcher's "
                    "Debug page, Game isolation off (LBPPC_APPCONTAINER=0), plays without it.\n", why);
    fflush(stdout);
    fflush(stderr);
    ExitProcess(CONTAINER_EXIT_CODE);
}

void runtime_container_start(void) {
    const char *setting = getenv("LBPPC_APPCONTAINER");
    if (setting && setting[0] == '0') {
        take_back();
        /* The profile too (its folder under %LOCALAPPDATA%\Packages); made again when isolation is back on. */
        if (SUCCEEDED(DeleteAppContainerProfile(CONTAINER_NAME)))
            puts("Container: AppContainer profile LBPPC.Game removed (isolation off)");
        return;
    }
    if (runtime_sandbox_in_container()) { /* the game, already inside: its controllers come from the broker */
        runtime_broker_attach();
        return;
    }
    const char *inside = getenv("LBPPC_CONTAINER");
    if (inside && inside[0] == '1') { /* started for it, but not in one: never run outside it unnoticed */
        give_up("the game was started for its AppContainer but is not in it");
        return;
    }

    if (local_server(getenv("LBPPC_SERVER")) || local_server(getenv("BB_SHADNET_SERVER"))) {
        give_up("the server is on this PC, which an AppContainer can't reach");
        return;
    }
    HRESULT hr = CreateAppContainerProfile(CONTAINER_NAME, L"LBPPC game", L"LittleBigPlanet 3 under LBPPC", NULL, 0,
                                           &container);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        hr = DeriveAppContainerSidFromAppContainerName(CONTAINER_NAME, &container);
    if (FAILED(hr)) {
        char why[96];
        snprintf(why, sizeof(why), "no AppContainer profile (0x%08lx)", (unsigned long)hr);
        give_up(why);
        return;
    }

    const ULONGLONG started = GetTickCount64();
    give_folders();
    if (grant_failures) {
        give_up("the game's folders could not all be given to it");
        return;
    }
    read_record(revoke_stale); /* what earlier runs gave and this one doesn't: taken back */
    write_record();
    printf("Container: folders given to AppContainer LBPPC.Game (%llu ms%s)\n",
           (unsigned long long)(GetTickCount64() - started), taken_back ? "; places no longer used taken back" : "");

    /* Network only: internetClient, internetClientServer (peers connect to us), privateNetworkClientServer (players
       on this network). */
    static const wchar_t *const names[] = {L"S-1-15-3-1", L"S-1-15-3-2", L"S-1-15-3-3"};
    SID_AND_ATTRIBUTES capabilities[3];
    for (int i = 0; i < 3; ++i) {
        ConvertStringSidToSidW(names[i], &capabilities[i].Sid);
        capabilities[i].Attributes = SE_GROUP_ENABLED;
    }
    SECURITY_CAPABILITIES security = {container, capabilities, 3, 0};
    /* AppContainer forces high-entropy ASLR, which put the first thread's stack inside the PS4 range every time;
       this executable is linked without it anyway. */
    static DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_OFF |
                            PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_OFF;
    /* The broker's shared memory: controllers in, rumble out (runtime_broker.c). */
    HANDLE section = runtime_broker_create();
    if (!section) fprintf(stderr, "Container: no shared memory for the controller broker (error %lu)\n", GetLastError());
    /* Only the standard handles (run.py's pipe) and the shared memory go in. */
    HANDLE handles[4];
    DWORD handle_count = 0;
    const DWORD which[] = {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE};
    for (int i = 0; i < 3; ++i) {
        HANDLE h = GetStdHandle(which[i]);
        int seen = 0;
        for (DWORD j = 0; j < handle_count; ++j) seen |= handles[j] == h;
        if (h && h != INVALID_HANDLE_VALUE && !seen && SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
            handles[handle_count++] = h;
    }
    if (section) handles[handle_count++] = section;
    const DWORD attribute_count = handle_count ? 3 : 2;
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, attribute_count, 0, &size);
    STARTUPINFOEXW si;
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.lpAttributeList = HeapAlloc(GetProcessHeap(), 0, size);
    if (!si.lpAttributeList || !InitializeProcThreadAttributeList(si.lpAttributeList, attribute_count, 0, &size) ||
        !UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security,
                                   sizeof(security), NULL, NULL) ||
        !UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy,
                                   sizeof(policy), NULL, NULL) ||
        (handle_count && !UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
                                                    handle_count * sizeof(HANDLE), NULL, NULL))) {
        char why[64];
        snprintf(why, sizeof(why), "its start-up attributes failed (error %lu)", GetLastError());
        give_up(why);
        return;
    }
    SetEnvironmentVariableW(L"LBPPC_CONTAINER", L"1");
    runtime_broker_child_environment(1);
    wchar_t *command = _wcsdup(GetCommandLineW());
    PROCESS_INFORMATION pi;
    fflush(stdout);
    fflush(stderr);
    const BOOL created = command && CreateProcessW(NULL, command, NULL, NULL, TRUE,
                                                   EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL,
                                                   &si.StartupInfo, &pi);
    const DWORD create_error = GetLastError();
    free(command);
    SetEnvironmentVariableW(L"LBPPC_CONTAINER", NULL);
    runtime_broker_child_environment(0);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    if (!created) {
        char why[64];
        snprintf(why, sizeof(why), "the game could not be started in it (error %lu)", create_error);
        give_up(why);
        return;
    }
    /* The game ends with this process (the launcher's Stop, run.py ending). */
    HANDLE job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        AssignProcessToJobObject(job, pi.hProcess);
    printf("Container: the game runs in AppContainer LBPPC.Game; controllers through the broker\n");
    fflush(stdout);
    ResumeThread(pi.hThread);
    runtime_broker_run(pi.hProcess); /* until the game ends */
    DWORD code = 21;
    GetExitCodeProcess(pi.hProcess, &code);
    ExitProcess(code);
}
#endif
