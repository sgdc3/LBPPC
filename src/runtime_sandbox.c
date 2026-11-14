/* lbppc: the game process's sandbox (Windows; nothing elsewhere). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"
#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#endif

/* lbppc: the game's code, and every level, object and file it reads from the server or from other players, runs here
 * natively, outside the PS4's sandbox, so before the game starts the process limits itself (Windows):
 * 1. A job of its own that allows no other process, and the child-process mitigation: an exploit cannot start a
 *    program (a shell, something it downloaded). DLLs are never loaded from the network or from a file a
 *    low-integrity process could have written.
 * 2. Low integrity, as a browser's tabs: from then on it writes only where it is let (labelled low): its own folders
 *    in user/ (saves, caches, logs, the game's temp0, download0 and data), user/trophies.log,
 *    lbppc.ini (the in-game menu) and input.ini. Not the launcher's settings (user/launcher.json), the modules or
 *    patches it loads, its program files, or anything else of the user's: an exploit cannot stay on the PC or plant
 *    code that runs outside. Reading is unchanged. Skipped, and said so, when a folder cannot be labelled (a drive
 *    without permissions, such as FAT or exFAT): the game would no longer save there.
 * Applied once, when the runtime attaches the game's main thread (runtime_thread_attach_main): after the process
 * may have started again for its memory range (runtime_memory.c) and its image is mapped, before any game code runs.
 * LBPPC_SANDBOX=0 turns both off (troubleshooting). */
#ifdef _WIN32
static int sandbox_is_low(const wchar_t *path, int dir) {
    PACL sacl=NULL;
    PSECURITY_DESCRIPTOR sd=NULL;
    int low=0;
    if (GetNamedSecurityInfoW(path,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,&sacl,&sd)==ERROR_SUCCESS && sacl) {
        for (DWORD i=0;i<sacl->AceCount;++i) {
            ACE_HEADER *ace;
            if (!GetAce(sacl,i,(void **)&ace) || ace->AceType!=SYSTEM_MANDATORY_LABEL_ACE_TYPE) continue;
            PSID sid=(PSID)&((SYSTEM_MANDATORY_LABEL_ACE *)ace)->SidStart;
            const DWORD rid=*GetSidSubAuthority(sid,*GetSidSubAuthorityCount(sid)-1);
            const BYTE inherit=OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE;
            if (rid==SECURITY_MANDATORY_LOW_RID && (!dir || (ace->AceFlags&inherit)==inherit)) low=1;
        }
    }
    if (sd) LocalFree(sd);
    return low;
}
/* A folder (and what it holds, and what is made in it later) or one file, writable at low integrity. */
static int sandbox_label_low(const wchar_t *path, int dir) {
    if (sandbox_is_low(path,dir)) return 1;
    PSECURITY_DESCRIPTOR sd=NULL;
    PACL sacl=NULL;
    BOOL present=FALSE, defaulted=FALSE;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(dir ? L"S:(ML;OICI;NW;;;LW)" : L"S:(ML;;NW;;;LW)",
                                                              SDDL_REVISION_1,&sd,NULL)) return 0;
    const int ok=GetSecurityDescriptorSacl(sd,&present,&sacl,&defaulted) && present &&
                 SetNamedSecurityInfoW((LPWSTR)path,SE_FILE_OBJECT,LABEL_SECURITY_INFORMATION,NULL,NULL,NULL,sacl)==ERROR_SUCCESS;
    LocalFree(sd);
    return ok;
}
static int sandbox_writable(const char *base, const char *name, int dir) {
    char narrow[MAX_PATH];
    wchar_t wide[MAX_PATH];
    snprintf(narrow,sizeof(narrow),"%s%s%s",base,*name ? "\\" : "",name);
    if (!MultiByteToWideChar(CP_ACP,0,narrow,-1,wide,MAX_PATH)) return 0;
    if (dir) CreateDirectoryW(wide,NULL);
    else if (GetFileAttributesW(wide)==INVALID_FILE_ATTRIBUTES) return 1; /* made later, if at all, by the launcher */
    if (sandbox_label_low(wide,dir)) return 1;
    fprintf(stderr,"Sandbox: %s cannot be made writable at low integrity (error %lu)\n",narrow,GetLastError());
    return 0;
}
#endif
void runtime_sandbox_install(void) {
#ifdef _WIN32
    static int installed;
    if (installed) return;
    installed=1;
    const char *setting=getenv("LBPPC_SANDBOX");
    if (setting && setting[0]=='0') { puts("Sandbox: off (LBPPC_SANDBOX=0)"); return; }

    int no_programs=1, local_dlls=1;
    HANDLE job=CreateJobObjectW(NULL,NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0};
    limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit=1;
    if (!job || !SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits)) ||
        !AssignProcessToJobObject(job,GetCurrentProcess())) {
        fprintf(stderr,"Sandbox: no job limiting processes (error %lu)\n",GetLastError());
        no_programs=0;
    }
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY child={0};
    child.NoChildProcessCreation=1;
    if (!SetProcessMitigationPolicy(ProcessChildProcessPolicy,&child,sizeof(child))) {
        fprintf(stderr,"Sandbox: child-process policy not set (error %lu)\n",GetLastError());
        no_programs=0;
    }
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY images={0};
    images.NoRemoteImages=1;
    images.NoLowMandatoryLabelImages=1;
    if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy,&images,sizeof(images))) {
        fprintf(stderr,"Sandbox: image-load policy not set (error %lu)\n",GetLastError());
        local_dlls=0;
    }

    /* What the game writes after this point (runtime_file.c, runtime_savedata.c, runtime_services.c, shadPS4's user
       folders, the DLSS data folder), in LBPPC's user folder and in shadPS4's (the same one
       unless LBPPC_USER_DIR is set). */
    static const char *const folders[]={"temp0","download0","data","savedata","cache","shader","log","dlss",
                                        "screenshots","captures","game_data","temp","home","download",
                                        "trophy"};
    /* shadPS4 makes these when first asked for a path, which may be later: made now, left as they are. */
    static const char *const read_only[]={"sys_modules","cheats","patches","custom_trophy","custom_configs","fonts",
                                          "custom_modules"};
    const char *bases[]={runtime_file_user_dir(),"user"};
    int labelled=1;
    for (int b=0;b<2;++b) {
        if (!bases[b] || !*bases[b] || (b==1 && !_stricmp(bases[0],"user"))) continue;
        CreateDirectoryA(bases[b],NULL);
        for (size_t i=0;i<sizeof(folders)/sizeof(*folders);++i) labelled&=sandbox_writable(bases[b],folders[i],1);
        for (size_t i=0;i<sizeof(read_only)/sizeof(*read_only);++i) {
            char path[MAX_PATH];
            snprintf(path,sizeof(path),"%s\\%s",bases[b],read_only[i]);
            CreateDirectoryA(path,NULL);
        }
    }
    const char *user=runtime_file_user_dir();
    char trophies[MAX_PATH];
    snprintf(trophies,sizeof(trophies),"%s\\trophies.log",user ? user : "user");
    FILE *f=fopen(trophies,"ab"); /* appended to on each trophy: made now so it can be labelled */
    if (f) fclose(f);
    labelled&=sandbox_writable(trophies,"",0);
    labelled&=sandbox_writable("lbppc.ini","",0);
    labelled&=sandbox_writable("input.ini","",0);

    int low=0;
    if (labelled) {
        /* Temporary files go to a folder it can still write. */
        char temp[MAX_PATH];
        snprintf(temp,sizeof(temp),"%s\\temp",user ? user : "user");
        char full[MAX_PATH];
        if (GetFullPathNameA(temp,sizeof(full),full,NULL)) {
            SetEnvironmentVariableA("TEMP",full);
            SetEnvironmentVariableA("TMP",full);
            char assignment[MAX_PATH+8];
            snprintf(assignment,sizeof(assignment),"TEMP=%s",full);
            _putenv(assignment);
            snprintf(assignment,sizeof(assignment),"TMP=%s",full);
            _putenv(assignment);
        }
        HANDLE token=NULL;
        PSID sid=NULL;
        if (OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_DEFAULT|TOKEN_QUERY,&token) &&
            ConvertStringSidToSidW(L"S-1-16-4096",&sid)) {
            TOKEN_MANDATORY_LABEL label={{sid,SE_GROUP_INTEGRITY}};
            low=SetTokenInformation(token,TokenIntegrityLevel,&label,sizeof(label)+GetLengthSid(sid));
        }
        if (!low) fprintf(stderr,"Sandbox: integrity not lowered (error %lu)\n",GetLastError());
        if (sid) LocalFree(sid);
        if (token) CloseHandle(token);
    } else {
        fputs("Sandbox: low integrity skipped (the folders above could not be labelled): the game keeps the user's "
              "own rights\n",stderr);
    }
    printf("Sandbox: %s; %s; %s\n",no_programs ? "no other programs" : "other programs allowed",
           local_dlls ? "DLLs from local files only" : "DLLs from anywhere",
           low ? "low integrity, writing only to its own folders" : "normal integrity");
#endif
}
