#include <windows.h>
#include <winnt.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// Use MSVC intrinsic for TEB (only works on x64)
#define NtCurrentPeb() ((PPEB)__readgsqword(0x60))

#pragma section("inject", read, execute)

// Hardcoded strings
__declspec(allocate("inject")) const char user32_name[] = "user32.dll";
__declspec(allocate("inject")) const char msgboxa_name[] = "MessageBoxA";
__declspec(allocate("inject")) const char loadlib_name[] = "LoadLibraryA";
__declspec(allocate("inject")) const char getproc_name[] = "GetProcAddress";
__declspec(allocate("inject")) const char msg_title[] = "Injected!";
__declspec(allocate("inject")) const char msg_text[] = "Hello from payload";

// Type definitions
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

// Retrieves kernel32 base address via PEB (no imports)
__declspec(code_seg("inject"))
HMODULE get_kernel32_base() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY moduleList = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = moduleList->Flink;

    while (current != moduleList) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        UNICODE_STRING* name = &entry->BaseDllName;

        if (name->Buffer && name->Length >= 24) { // Enough for "kernel32.dll"
            WCHAR buf[13] = {0};
            for (int i = 0; i < 12 && i < name->Length / 2; i++) {
                WCHAR c = name->Buffer[i];
                buf[i] = (c >= L'A' && c <= L'Z') ? c + 32 : c;
            }
            if (wcsncmp(buf, L"kernel32.dll", 12) == 0) {
                return (HMODULE)entry->DllBase;
            }
        }
        current = current->Flink;
    }
    return NULL;
}

// Resolve function address by name from export table
__declspec(code_seg("inject"))
FARPROC resolve_export(HMODULE module, const char* name) {
    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);

    DWORD* name_rvas = (DWORD*)(base + exports->AddressOfNames);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* func_name = (const char*)(base + name_rvas[i]);
        if (lstrcmpA(func_name, name) == 0) {
            WORD ordinal = ordinals[i];
            return (FARPROC)(base + functions[ordinal]);
        }
    }
    return NULL;
}

// Entry point of payload
__declspec(code_seg("inject"))
int main_payload(int unused) {
    HMODULE kernel32 = get_kernel32_base();
    if (!kernel32) return -1;

    // Resolve LoadLibraryA and GetProcAddress manually
    pLoadLibraryA LoadLibraryA_ = (pLoadLibraryA)resolve_export(kernel32, loadlib_name);
    pGetProcAddress GetProcAddress_ = (pGetProcAddress)resolve_export(kernel32, getproc_name);
    if (!LoadLibraryA_ || !GetProcAddress_) return -2;

    // Load user32.dll
    HMODULE user32 = LoadLibraryA_(user32_name);
    if (!user32) return -3;

    // Resolve MessageBoxA
    pMessageBoxA MessageBoxA_ = (pMessageBoxA)GetProcAddress_(user32, msgboxa_name);
    if (!MessageBoxA_) return -4;

    // Show message box
    MessageBoxA_(NULL, msg_text, msg_title, MB_OK | MB_ICONINFORMATION);

    return 2600 + unused;
}
