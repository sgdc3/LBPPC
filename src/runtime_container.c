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
 * game runs as before and the log says why; =require stops instead. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

#ifndef _WIN32
void runtime_container_start(void) {}
#else
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <psapi.h>
#include <shellapi.h>
#include <wchar.h>

#define CONTAINER_NAME L"LBPPC.Game"
#define READ_ACCESS (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
#define WRITE_ACCESS (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_GENERIC_WRITE | DELETE)
/* The user folder itself: its attributes and the names in it, not its files' contents. */
#define USER_FOLDER_ACCESS (FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE | READ_CONTROL)

static PSID container;
static int grant_failures;
/* The game runs without the container this time: what earlier runs gave it is taken back instead (take_back). */
static int taking_back, taken_back;
static void revoke_w(const wchar_t *path, int any);

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
 * grant, or (any=0) only one its contents inherit (the whole folder, as LBPPC gave it before the broker kept the key). */
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

static int loopback_server(const char *value) {
    return value && (strstr(value, "127.") || strstr(value, "localhost") || strstr(value, "[::1]"));
}

/* What it reads: the program and its DLLs, and every file or folder named on the command line (the prepared game in
 * out/, the game, its update). Not the whole user folder, which holds the launcher's settings and this PC's identity
 * key (kept by the broker): its folders and files one by one, to read or to write, as runtime_sandbox_prepare lists
 * them. With taking_back, the same walk takes it all back. */
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
            revoke_w(argv[i + 1], 0); /* given whole by LBPPC before the broker kept the key */
            /* The folder itself, not what it holds: its attributes and names (shadPS4 checks it exists). */
            grant_w(argv[i + 1], USER_FOLDER_ACCESS, 0);
            ++i;
            continue;
        }
        grant_read(argv[i]);
    }
    if (argv) LocalFree(argv);
    revoke_w(L"user", 0);
    grant_w(L"user", USER_FOLDER_ACCESS, 0);
    if (!runtime_sandbox_prepare(user, grant_prepared)) ++grant_failures;
    /* The identity key's folder was writable for the container before the broker kept the key: taken back. */
    const char *key_folders[] = {user, "user"};
    for (int i = 0; i < 2; ++i) {
        char narrow[MAX_PATH];
        wchar_t wide[MAX_PATH];
        snprintf(narrow, sizeof(narrow), "%s\\online_keys", key_folders[i]);
        if (MultiByteToWideChar(CP_ACP, 0, narrow, -1, wide, MAX_PATH)) revoke_w(wide, 0);
    }
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
    if (taken_back)
        printf("Container: what earlier runs gave AppContainer LBPPC.Game taken back (%d places, %llu ms)\n",
               taken_back, (unsigned long long)(GetTickCount64() - started));
}

static void give_up(const char *why, int require) {
    fprintf(stderr, "Container: %s; %s\n", why,
            require ? "LBPPC_APPCONTAINER=require: stopping" : "the game runs without it");
    fflush(stderr);
    if (require) ExitProcess(21);
    take_back();
}

void runtime_container_start(void) {
    const char *setting = getenv("LBPPC_APPCONTAINER");
    if (setting && setting[0] == '0') {
        take_back();
        return;
    }
    const int require = setting && !strcmp(setting, "require");
    if (runtime_sandbox_in_container()) { /* the game, already inside: its controllers come from the broker */
        runtime_broker_attach();
        return;
    }
    const char *inside = getenv("LBPPC_CONTAINER");
    if (inside && inside[0] == '1') return;     /* started for it, but not in one: run as is */

    if (loopback_server(getenv("LBPPC_SERVER")) || loopback_server(getenv("BB_SHADNET_SERVER"))) {
        give_up("the server is on this PC, which an AppContainer can't reach", require);
        return;
    }
    HRESULT hr = CreateAppContainerProfile(CONTAINER_NAME, L"LBPPC game", L"LittleBigPlanet 3 under LBPPC", NULL, 0,
                                           &container);
    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
        hr = DeriveAppContainerSidFromAppContainerName(CONTAINER_NAME, &container);
    if (FAILED(hr)) {
        char why[96];
        snprintf(why, sizeof(why), "no AppContainer profile (0x%08lx)", (unsigned long)hr);
        give_up(why, require);
        return;
    }

    const ULONGLONG started = GetTickCount64();
    give_folders();
    if (grant_failures) {
        give_up("the game's folders could not all be given to it", require);
        return;
    }
    printf("Container: folders given to AppContainer LBPPC.Game (%llu ms)\n",
           (unsigned long long)(GetTickCount64() - started));

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
    runtime_broker_load_identity(); /* this PC's identity key stays out here */
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
        give_up(why, require);
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
        give_up(why, require);
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
