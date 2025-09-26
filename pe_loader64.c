//compile .c to .exe: gcc -o pe_loader64.exe pe_loader64.c -static -O2 
//need to install mingw-w64 first ( USE MSYS2 UCRT64 TO COMPILE 64-BIT PROGRAM)

#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>


// ============================================================================
// PROTOTYPES 
// ============================================================================
bool ValidateFilePath(const char* filePath);
bool ValidatePE64(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS64 pNtHeaders, DWORD fileSize);
bool CopySections64(LPVOID pFileBuffer, LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders);
bool ProcessRelocations64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders);
bool ProcessImports64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders);
bool ExecuteTLSCallbacks64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders);
bool SetSectionPermissions64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders);
void DisplayFileInfo64(const char* filePath, PIMAGE_NT_HEADERS64 pNtHeaders);
void CleanupResources(LPVOID pImageBase, LPVOID pFileBuffer, HANDLE hMapping, HANDLE hFile);

// 64-bit NT Headers
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// ============================================================================
// CUSTOM MACROS FOR 64-BIT
// ============================================================================

// Macro cho 64-bit section header (sửa lỗi IMAGE_FIRST_SECTION64)
#define IMAGE_FIRST_SECTION64(ntheader) ((PIMAGE_SECTION_HEADER) \
    ((ULONG_PTR)(ntheader) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + \
     ((ntheader))->FileHeader.SizeOfOptionalHeader))

#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif

// 64-bit exception handling
jmp_buf env64;

LONG __stdcall exception_filter_64(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    printf("[EXCEPTION] Code: 0x%08X at Address: 0x%016llX\n", 
           ExceptionInfo->ExceptionRecord->ExceptionCode,
           (ULONGLONG)ExceptionInfo->ExceptionRecord->ExceptionAddress);
    longjmp(env64, 1);
    return EXCEPTION_EXECUTE_HANDLER;
}

// ============================================================================
// get&validate filePath 
// ============================================================================

bool GetFilePathFromUser(char* filePath, int bufferSize) {
    printf("Please enter the path to the 64-bit PE file (.exe):\n");
    printf("> ");
    
    if (fgets(filePath, bufferSize, stdin) == NULL) {
        printf("[ERROR] Failed to read input\n");
        return false;
    }

    // Xóa ký tự newline ở cuối    
    size_t len = strlen(filePath);
    if (len > 0 && filePath[len - 1] == '\n') {
        filePath[len - 1] = '\0';
    }
    
    if (strlen(filePath) == 0) {
        printf("[ERROR] No file path entered\n");
        return false;
    }
    
    // SỬA LỖI: Kiểm tra an toàn cho dấu ngoặc kép
    if (len >= 2 && filePath[0] == '\"' && filePath[len - 1] == '\"') {
        memmove(filePath, filePath + 1, len - 2);
        filePath[len - 2] = '\0';
    }
    
    return ValidateFilePath(filePath);
}

bool ValidateFilePath(const char* filePath) {
    if (strlen(filePath) == 0) {
        printf("[ERROR] File path is empty\n");
        return false;
    }
    
    if (strlen(filePath) > MAX_PATH - 1) {
        printf("[ERROR] File path too long (max %d characters)\n", MAX_PATH - 1);
        return false;
    }
    
    // Kiểm tra ký tự không hợp lệ (bỏ qua 3 ký tự đầu)
    const char* invalidChars = "<>:\"|?*";
    size_t pathLen = strlen(filePath);
    size_t startIdx = (pathLen > 3) ? 3 : 0;

    for (size_t i = startIdx; i < pathLen; i++) {
        for (size_t j = 0; j < strlen(invalidChars); j++) {
            if (filePath[i] == invalidChars[j]) {
                printf("[ERROR] File path contains invalid character: '%c' (pos %zu)\n", invalidChars[j], i);
                return false;
            }
        }
    }

    DWORD fileAttributes = GetFileAttributesA(filePath);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        printf("[ERROR] File does not exist or cannot be accessed: %s\n", filePath);
        return false;
    }
    
    if (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        printf("[ERROR] Path is a directory, not a file: %s\n", filePath);
        return false;
    }
    
    const char* ext = strrchr(filePath, '.');
    if (ext == NULL || _stricmp(ext, ".exe") != 0) {
        printf("[WARNING] File extension is not .exe: %s\n", filePath);
        printf("          This may not be a valid PE executable\n");
    }

    // Kiểm tra quyền truy cập file
    HANDLE testFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (testFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Cannot open file for reading (access denied): %s\n", filePath);
        return false;
    }
    CloseHandle(testFile);
    
    printf("[SUCCESS] File path validation passed: %s\n", filePath);
    return true;
}



void CleanupResources(LPVOID pImageBase, LPVOID pFileBuffer, HANDLE hMapping, HANDLE hFile) {
    printf("[CLEANUP] Releasing allocated resources...\n");
    
    if (pImageBase) {
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        printf("  Freed image memory at 0x%p\n", pImageBase);
    }
    
    if (pFileBuffer) {
        UnmapViewOfFile(pFileBuffer);
        printf("  Unmapped file view\n");
    }
    
    if (hMapping && hMapping != INVALID_HANDLE_VALUE) {
        CloseHandle(hMapping);
        printf("  Closed file mapping\n");
    }
    
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        printf("  Closed file handle\n");
    }
    
    printf("[SUCCESS] Cleanup completed\n");
}

// ============================================================================
// HÀM VALIDATE PE 64-BIT
// ============================================================================

bool ValidatePE64(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS64 pNtHeaders, DWORD fileSize) {
    if (pDosHeader->e_magic != 0x5A4D) {
        printf("[ERROR] Invalid DOS signature\n");
        return false;
    }
    
    // KIỂM TRA e_lfanew
    if (pDosHeader->e_lfanew > fileSize - sizeof(IMAGE_NT_HEADERS64)) {
        printf("[ERROR] Invalid e_lfanew value: 0x%X\n", pDosHeader->e_lfanew);
        return false;
    }

    if (pNtHeaders->Signature != 0x00004550) {
        printf("[ERROR] Invalid PE signature\n");
        return false;
    }
    
    // Kiểm tra architecture 64-bit (0x8664 = AMD64)
    if (pNtHeaders->FileHeader.Machine != 0x8664) {
        printf("[ERROR] Only 64-bit PE files supported (0x8664)\n");
        return false;
    }
    
    if (pNtHeaders->FileHeader.NumberOfSections > 96) {
        printf("[ERROR] Suspicious number of sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
        return false;
    }
    
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint >= pNtHeaders->OptionalHeader.SizeOfImage) {
        printf("[ERROR] Entry Point RVA exceeds image size\n");
        return false;
    }
    
    printf("[SUCCESS] 64-bit PE file validation passed\n");
    return true;
}


// ============================================================================
// HÀM COPY SECTIONS 64-BIT
// ============================================================================

bool CopySections64(LPVOID pFileBuffer, LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders) {
    DWORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION64(pNtHeaders);
    
    printf("\n=== COPYING 64-BIT SECTIONS ===\n");
    printf("[INFO] Copying %d sections...\n", numberOfSections);
    
    // Copy PE headers
    DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    memcpy(pImageBase, pFileBuffer, sizeOfHeaders);
    
    // Copy từng section
    for (DWORD i = 0; i < numberOfSections; i++) {
        LPVOID dest = (BYTE*)pImageBase + sectionHeader[i].VirtualAddress;
        DWORD rawSize = sectionHeader[i].SizeOfRawData;
        DWORD virtualSize = sectionHeader[i].Misc.VirtualSize;
        
        if (rawSize > 0) {
            LPVOID src = (BYTE*)pFileBuffer + sectionHeader[i].PointerToRawData;
            DWORD copySize = (rawSize < virtualSize) ? rawSize : virtualSize;
            memcpy(dest, src, copySize);
            
            // Zero-fill phần còn lại
            if (virtualSize > copySize) {
                memset((BYTE*)dest + copySize, 0, virtualSize - copySize);
            }
        } else {
            // Section không có dữ liệu trong file
            memset(dest, 0, virtualSize);
        }
        
        printf("  %-8s  | VSz=0x%08X |  VA=0x%08X  |  RawSz=0x%08X | RawPtr=0x%08X | Flags=0x%08X\n",
               sectionHeader[i].Name,
               sectionHeader[i].Misc.VirtualSize,
               sectionHeader[i].VirtualAddress,
               sectionHeader[i].SizeOfRawData,
               sectionHeader[i].PointerToRawData,
               sectionHeader[i].Characteristics);
    }
    
    return true;
}

// ============================================================================
// HÀM SET PERMISSIONS 64-BIT 
// ============================================================================

bool SetSectionPermissions64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders) {
    DWORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION64(pNtHeaders);
    
    printf("[INFO] Setting 64-bit section permissions...\n");
    
    for (DWORD i = 0; i < numberOfSections; i++) {
        DWORD protect = 0;
        BOOL executable = (sectionHeader[i].Characteristics & 0x20000000) != 0;
        BOOL writable = (sectionHeader[i].Characteristics & 0x80000000) != 0;
        BOOL readable = (sectionHeader[i].Characteristics & 0x40000000) != 0;
        
        if (executable && writable) protect = PAGE_EXECUTE_READWRITE;
        else if (executable && readable) protect = PAGE_EXECUTE_READ;
        else if (executable) protect = PAGE_EXECUTE;
        else if (writable) protect = PAGE_READWRITE;
        else if (readable) protect = PAGE_READONLY;
        else protect = PAGE_NOACCESS;
        
        DWORD oldProtect;
        LPVOID sectionAddress = (BYTE*)pImageBase + sectionHeader[i].VirtualAddress;
        DWORD sectionSize = sectionHeader[i].Misc.VirtualSize;
        
        if (sectionSize > 0) {
            if (VirtualProtect(sectionAddress, sectionSize, protect, &oldProtect)) {
                const char* permStr = "RO";
                if (protect == PAGE_EXECUTE_READ) permStr = "RX";
                else if (protect == PAGE_READWRITE) permStr = "RW";
                else if (protect == PAGE_EXECUTE_READWRITE) permStr = "RWX";
                
                printf("  %-8s: 0x%p -> %s\n", sectionHeader[i].Name, sectionAddress, permStr);
            } else {
                printf("[WARNING] Failed to set permissions for section %s\n", sectionHeader[i].Name);
            }
        }
    }
    
    return true;
}



// ============================================================================
// HÀM RELOCATION 64-BIT (change a bit)
// ============================================================================

bool ProcessRelocations64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders) {
    ULONGLONG preferredBase = pNtHeaders->OptionalHeader.ImageBase;
    ULONGLONG actualBase = (ULONGLONG)pImageBase;
    LONGLONG delta = actualBase - preferredBase;
    
    if (delta == 0) {
        printf("[INFO] Image loaded at preferred base 0x%016llX, no relocation needed\n", preferredBase);
        return true;
    }
    
    printf("[INFO] Applying 64-bit relocations: Delta = 0x%016llX\n", delta);
    
    DWORD relocRVA = pNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress;
    DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[5].Size;

    // Kiểm tra có relocation table không
    if (relocRVA == 0 || relocSize == 0) {
        printf("[WARNING] No relocation table found\n");
        return true;
    }
    
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pImageBase + relocRVA);
    DWORD totalProcessed = 0;
    
    while ((ULONGLONG)pReloc - (ULONGLONG)pImageBase < relocRVA + relocSize && pReloc->SizeOfBlock > 0) {
        DWORD itemsCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocationItems = (WORD*)(pReloc + 1);
        
        DWORD blockBase = pReloc->VirtualAddress;
        
        for (DWORD i = 0; i < itemsCount; i++) {
            WORD item = relocationItems[i];
            BYTE type = item >> 12;
            WORD offset = item & 0xFFF;
            
            // 64-bit dùng DIR64 thay vì HIGHLOW
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patchAddress = (ULONGLONG*)((BYTE*)pImageBase + blockBase + offset);
                
                if ((ULONGLONG)patchAddress >= (ULONGLONG)pImageBase && 
                    (ULONGLONG)patchAddress <= (ULONGLONG)pImageBase + pNtHeaders->OptionalHeader.SizeOfImage - sizeof(ULONGLONG)) {
                    *patchAddress += delta;
                    totalProcessed++;
                }
            }
        }
        
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }
    
    printf("[SUCCESS] Applied %d 64-bit relocations\n", totalProcessed);
    return true;
}

// ============================================================================
// HÀM IMPORT 64-BIT (no change)
// ============================================================================

bool ProcessImports64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders) {
    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;
    
    if (importRVA == 0) {
        printf("[INFO] No imports found\n");
        return true;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImageBase + importRVA);
    DWORD dllCount = 0;
    DWORD funcCount = 0;
    
    printf("[INFO] Processing 64-bit imports...\n");
    
    // Duyệt qua từng DLL trong import table (kết thúc bằng NULL)    
    while (importDesc->Name != 0) {
        const char* dllName = (const char*)((BYTE*)pImageBase + importDesc->Name);
        printf("  Loading DLL: %s\n", dllName);
        
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            printf("[ERROR] Failed to load DLL: %s (Error: %d)\n", dllName, GetLastError());
            return false;
        }
        
        PIMAGE_THUNK_DATA64 thunk = NULL;
        if (importDesc->OriginalFirstThunk != 0) {
            thunk = (PIMAGE_THUNK_DATA64)((BYTE*)pImageBase + importDesc->OriginalFirstThunk);
        } else {
            thunk = (PIMAGE_THUNK_DATA64)((BYTE*)pImageBase + importDesc->FirstThunk);
        }
            
        PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)((BYTE*)pImageBase + importDesc->FirstThunk);
        
        // Duyệt qua từng hàm import trong DLL
        while (thunk->u1.AddressOfData != 0) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // import bằng ordinal
                UINT ordinal = IMAGE_ORDINAL64(thunk->u1.Ordinal);
                PROC func = (PROC)GetProcAddress(hModule, (LPCSTR)MAKELPARAM(ordinal,0));
                if (!func) {
                    printf("[ERROR] Failed to get function by ordinal %d in %s\n", ordinal, dllName);
                    FreeLibrary(hModule);
                    return false;
                }
                iat->u1.Function = (ULONGLONG)func;
                printf("    Ordinal %d -> 0x%016llX\n", ordinal, (ULONGLONG)func);
            } else {
                // import bằng tên hàm
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pImageBase + thunk->u1.AddressOfData);
                PROC func = (PROC)GetProcAddress(hModule, (LPCSTR)importByName->Name);
                if (!func) {
                    printf("[ERROR] Failed to get function %s in %s\n", importByName->Name, dllName);
                    FreeLibrary(hModule);
                    return false;
                }
                iat->u1.Function = (ULONGLONG)func;
                printf("    %s -> 0x%016llX\n", importByName->Name, (ULONGLONG)func);
            }
            funcCount++;
            thunk++;
            iat++;
        }
        
        dllCount++;
        importDesc++;
    }
    
    printf("[SUCCESS] 64-bit import resolution completed: %d DLLs, %d functions\n", dllCount, funcCount);
    return true;
}

// ============================================================================
// HÀM TLS CALLBACKS 64-BIT (no change)
// ============================================================================

bool ExecuteTLSCallbacks64(LPVOID pImageBase, PIMAGE_NT_HEADERS64 pNtHeaders) {
    DWORD tlsRVA = pNtHeaders->OptionalHeader.DataDirectory[9].VirtualAddress;
    
    if (tlsRVA == 0) {
        printf("[INFO] No TLS Callbacks found\n");
        return true;
    }
    
    PIMAGE_TLS_DIRECTORY64 tlsDir = (PIMAGE_TLS_DIRECTORY64)((BYTE*)pImageBase + tlsRVA);
    PULONGLONG callbackArray = (PULONGLONG)tlsDir->AddressOfCallBacks;
    
    if (callbackArray == NULL || (ULONGLONG)callbackArray == 0) {
        printf("[INFO] TLS Directory present but no callbacks\n");
        return true;
    }
    
    printf("[INFO] Executing 64-bit TLS Callbacks...\n");
    DWORD callbackCount = 0;
    
    // SỬA: Chỉ add handler nếu chưa có
    PVOID handler = NULL;
    if (!IsDebuggerPresent()) { // Chỉ add handler nếu không debug
        handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exception_filter_64);
    }
    

    while (*callbackArray != 0 && *callbackArray != (ULONGLONG)NULL) {
        VOID (NTAPI *tlsCallback)(PVOID DllHandle, DWORD Reason, PVOID Reserved) = 
            (VOID (NTAPI *)(PVOID, DWORD, PVOID))(*callbackArray);
        
        if (tlsCallback) {
            printf("  Calling 64-bit TLS Callback #%d at 0x%016llX\n", callbackCount + 1, (ULONGLONG)tlsCallback);
            
            if (setjmp(env64) == 0) {
                tlsCallback(pImageBase, DLL_PROCESS_ATTACH, NULL);
                callbackCount++;
            } else {
                printf("[WARNING] 64-bit TLS Callback #%d caused exception\n", callbackCount + 1);
            }
        }
        
        callbackArray++;
    }
    
    if (handler) {
        RemoveVectoredExceptionHandler(handler);
    }
    
    printf("[SUCCESS] Executed %d 64-bit TLS Callbacks\n", callbackCount);
    return true;
}

// ============================================================================
// HÀM HIỂN THỊ THÔNG TIN 64-BIT
// ============================================================================

void DisplayFileInfo64(const char* filePath, PIMAGE_NT_HEADERS64 pNtHeaders) {
    printf("\n=== 64-BIT FILE INFORMATION ===\n");
    printf("File: %s\n", filePath);
    printf("Architecture: 64-bit (AMD64)\n");
    printf("Sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("Image Base: 0x%016llX\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("Entry Point: 0x%08X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("Image Size: 0x%08X bytes\n", pNtHeaders->OptionalHeader.SizeOfImage);
    printf("Subsystem: %d\n", pNtHeaders->OptionalHeader.Subsystem);
    printf("Characteristics: 0x%04X\n", pNtHeaders->FileHeader.Characteristics);
}

// ============================================================================
// MAIN FUNCTION CHO 64-BIT LOADER
// ============================================================================

int main() {
    printf("=== 64-BIT ADVANCED PE LOADER ===\n");
    
    char peFilePath[MAX_PATH] = {0};
    LPVOID pFileBuffer = NULL;
    HANDLE hMapping = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPVOID pImageBase = NULL;
    
    if (!GetFilePathFromUser(peFilePath, sizeof(peFilePath))) {
        printf("[ERROR] Invalid file path\n");
        return 1;
    }

    hFile = CreateFileA(peFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Cannot open file: %s (Error: %d)\n", peFilePath, GetLastError());
        return 1;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[ERROR] Invalid file size\n");
        CleanupResources(NULL, NULL, NULL, hFile);
        return 1;
    }
    
    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printf("[ERROR] CreateFileMapping failed (Error: %d)\n", GetLastError());
        CleanupResources(NULL, NULL, NULL, hFile);
        return 1;
    }
    
    pFileBuffer = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, fileSize);
    if (!pFileBuffer) {
        printf("[ERROR] MapViewOfFile failed (Error: %d)\n", GetLastError());
        CleanupResources(NULL, NULL, hMapping, hFile);
        return 1;
    }
    
    printf("[SUCCESS] File mapped at 0x%p, size: 0x%08X bytes\n", pFileBuffer, fileSize);
    
    // Parse PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDosHeader->e_magic != 0x5A4D) {
        printf("[ERROR] Not a valid DOS executable\n");
        CleanupResources(NULL, pFileBuffer, hMapping, hFile);
        return 1;
    }
    
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
    
    if (!ValidatePE64(pDosHeader, pNtHeaders, fileSize)) {
        CleanupResources(NULL, pFileBuffer, hMapping, hFile);
        return 1;
    }

    DisplayFileInfo64(peFilePath, pNtHeaders);
    
    // Cấp phát bộ nhớ cho PE image
    ULONGLONG imageBase = pNtHeaders->OptionalHeader.ImageBase;
    DWORD sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    
    printf("[INFO] Preferred base: 0x%016llX, Image size: 0x%08X\n", imageBase, sizeOfImage);
    
    // Cấp phát bộ nhớ 64-bit
    pImageBase = VirtualAlloc((LPVOID)imageBase, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pImageBase) {
        printf("[INFO] Cannot allocate at preferred base, trying system choice...\n");
        pImageBase = VirtualAlloc(NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pImageBase) {
            printf("[ERROR] VirtualAlloc failed for size 0x%08X (Error: %d)\n", sizeOfImage, GetLastError());
            CleanupResources(NULL, pFileBuffer, hMapping, hFile);
            return 1;
        }
    }
    
    printf("[SUCCESS] 64-bit Image allocated at 0x%p\n", pImageBase);

    bool success = false;
    //Chỉ add exception handler một lần
    PVOID main_handler = NULL;
    if (!IsDebuggerPresent()) {
        main_handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exception_filter_64);
    }
    // Sử dụng setjmp/longjmp để bắt exception
    if (setjmp(env64) == 0) {
        // Sử dụng các hàm 64-bit 
        if (!CopySections64(pFileBuffer, pImageBase, pNtHeaders)) {
            printf("[ERROR] Failed to copy sections\n");
            success = false;
        }
        else if (!ProcessRelocations64(pImageBase, pNtHeaders)) {
            printf("[ERROR] 64-bit Relocation failed\n");
            success = false;
        }
        else if (!ProcessImports64(pImageBase, pNtHeaders)) {
            printf("[ERROR] 64-bit Import resolution failed\n");
            success = false;
        }
        else if (!ExecuteTLSCallbacks64(pImageBase, pNtHeaders)) {
            printf("[ERROR] 64-bit TLS Callbacks execution failed\n");
            success = false;
        }
        else if (!SetSectionPermissions64(pImageBase, pNtHeaders)) {
            printf("[WARNING] Section permission setting had issues\n");
            success = true;
        } else {
            success = true;
        }
    } else {
        printf("[ERROR] Exception occurred during 64-bit PE loading\n");
        success = false;
    }
    
    if (main_handler) {
        RemoveVectoredExceptionHandler(main_handler);
    }
    
    if (!success) {
        CleanupResources(pImageBase, pFileBuffer, hMapping, hFile);
        return 1;
    }
    
    printf("\n=== 64-BIT EXECUTION READY ===\n");
    printf("Entry Point: 0x%p\n", (BYTE*)pImageBase + entryPointRVA);
    
    printf("Press:\n");
    printf("  1 - Execute 64-bit program\n");
    printf("  2 - Exit without execution\n");
    
    int choice = getchar();
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    if (choice == '1') {
        printf("\n[EXECUTING] Transferring control to 64-bit entry point...\n");
        
        //Chỉ add exception handler một lần
        PVOID exec_handler = NULL;
        if (!IsDebuggerPresent()) {
            exec_handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exception_filter_64);
        }

        if (setjmp(env64) == 0) {
            void (*entryPoint)() = (void(*)())((BYTE*)pImageBase + entryPointRVA);
            entryPoint();
            printf("[INFO] 64-bit program execution completed normally\n");
        } else {
            printf("[EXCEPTION] 64-bit program caused exception during execution\n");
        }
        
        if (exec_handler) {
            RemoveVectoredExceptionHandler(exec_handler);
        }
    } else {
        printf("[INFO] 64-bit execution cancelled by user\n");
    }
    
    CleanupResources(pImageBase, pFileBuffer, hMapping, hFile);
    
    printf("Press Enter to exit...\n");
    getchar(); getchar();
    
    return 0;
}