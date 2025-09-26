#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <setjmp.h>

// ============================================================================
// 2.2 PE Loader (.exe)
// ============================================================================

#define WIN32_LEAN_AND_MEAN  // Giảm thiểu include không cần thiết

// Chỉ định nghĩa các struct không có sẵn hoặc cần custom
typedef struct _IMAGE_TLS_DIRECTORY32 {
    DWORD StartAddressOfRawData;
    DWORD EndAddressOfRawData;
    DWORD AddressOfIndex;
    DWORD AddressOfCallBacks;
    DWORD SizeOfZeroFill;
    DWORD Characteristics;
} IMAGE_TLS_DIRECTORY32, *PIMAGE_TLS_DIRECTORY32;

// Macro cần thiết (kiểm tra trước khi định nghĩa để tránh conflict)
#ifndef IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL_FLAG32 0x80000000
#endif

#ifndef IMAGE_ORDINAL32
#define IMAGE_ORDINAL32(ordinal) ((ordinal) & 0xFFFF)
#endif

#define IMAGE_REL_BASED_HIGHLOW 3

// Custom IMAGE_FIRST_SECTION macro (chỉ định nghĩa nếu chưa có)
#ifndef IMAGE_FIRST_SECTION
#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) \
    ((ULONG_PTR)(ntheader) + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + \
     ((ntheader))->FileHeader.SizeOfOptionalHeader))
#endif

// Biến toàn cục cho exception handling (thay thế __try/__except của MSVC)
jmp_buf env;

// Hàm xử lý exception thay thế cho __except (sử dụng __stdcall cho compatibility)
LONG __stdcall exception_filter(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    printf("[EXCEPTION] Code: 0x%08X at Address: 0x%08X\n", 
           ExceptionInfo->ExceptionRecord->ExceptionCode,
           ExceptionInfo->ExceptionRecord->ExceptionAddress);
    longjmp(env, 1);  // Nhảy về điểm setjmp
    return EXCEPTION_EXECUTE_HANDLER;
}

// ============================================================================
// HÀM VALIDATE PE FILE
// ============================================================================

bool ValidatePE(PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNtHeaders, DWORD fileSize) {
    // Kiểm tra signature "MZ"
    if (pDosHeader->e_magic != 0x5A4D) {
        printf("[ERROR] Invalid DOS signature (not MZ)\n");
        return false;
    }
    
    // Kiểm tra signature "PE"
    if (pNtHeaders->Signature != 0x00004550) {
        printf("[ERROR] Invalid PE signature\n");
        return false;
    }
    
    // Chỉ hỗ trợ file 32-bit (0x014C = IMAGE_FILE_MACHINE_I386)
    if (pNtHeaders->FileHeader.Machine != 0x014C) {
        printf("[ERROR] Only 32-bit PE files supported\n");
        return false;
    }
    
    // Kiểm tra số section hợp lý (tránh file độc hại)
    if (pNtHeaders->FileHeader.NumberOfSections > 96) {
        printf("[ERROR] Suspicious number of sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
        return false;
    }
    
    // Kiểm tra entry point không vượt quá kích thước image
    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint >= pNtHeaders->OptionalHeader.SizeOfImage) {
        printf("[ERROR] Entry Point RVA exceeds image size\n");
        return false;
    }
    
    printf("[SUCCESS] PE file validation passed\n");
    return true;
}

// ============================================================================
// HÀM CLEANUP TÍCH HỢP - XỬ LÝ DỌN DẸP TÀI NGUYÊN
// ============================================================================

void CleanupResources(LPVOID pImageBase, LPVOID pFileBuffer, HANDLE hMapping, HANDLE hFile) {
    printf("[CLEANUP] Releasing allocated resources...\n");
    
    // Giải phóng memory đã cấp phát cho PE image
    if (pImageBase) {
        VirtualFree(pImageBase, 0, MEM_RELEASE);
        printf("  Freed image memory at 0x%p\n", pImageBase);
    }
    
    // Unmap file mapping
    if (pFileBuffer) {
        UnmapViewOfFile(pFileBuffer);
        printf("  Unmapped file view\n");
    }
    
    // Đóng handle file mapping
    if (hMapping && hMapping != INVALID_HANDLE_VALUE) {
        CloseHandle(hMapping);
        printf("  Closed file mapping\n");
    }
    
    // Đóng handle file
    if (hFile && hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        printf("  Closed file handle\n");
    }
    
    printf("[SUCCESS] Cleanup completed\n");
}

// ============================================================================
// HÀM XỬ LÝ RELOCATION 
// ============================================================================

bool ProcessRelocations(LPVOID pImageBase, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD preferredBase = pNtHeaders->OptionalHeader.ImageBase;  // Base address mong muốn
    DWORD actualBase = (DWORD)pImageBase;                        // Base address thực tế
    DWORD delta = actualBase - preferredBase;                    // Độ chênh lệch
    
    // Nếu load đúng base address mong muốn thì không cần relocation
    if (delta == 0) {
        printf("[INFO] Image loaded at preferred base 0x%08X, no relocation needed\n", preferredBase);
        return true;
    }
    
    printf("[INFO] Applying relocations: Delta = 0x%08X\n", delta);
    
    // Lấy thông tin relocation directory (index 5)
    DWORD relocRVA = pNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress;
    DWORD relocSize = pNtHeaders->OptionalHeader.DataDirectory[5].Size;
    
    // Kiểm tra có relocation table không
    if (relocRVA == 0 || relocSize == 0) {
        printf("[WARNING] No relocation table found\n");
        return true;
    }
    
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pImageBase + relocRVA);
    DWORD totalProcessed = 0;
    
    // Duyệt qua các block relocation
    while ((DWORD)pReloc - (DWORD)pImageBase < relocRVA + relocSize && pReloc->SizeOfBlock > 0) {
        DWORD itemsCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocationItems = (WORD*)(pReloc + 1);  // Danh sách relocation items sau header
        
        DWORD blockBase = pReloc->VirtualAddress;  // Base RVA cho block này
        
        // Xử lý từng relocation item trong block
        for (DWORD i = 0; i < itemsCount; i++) {
            WORD item = relocationItems[i];
            BYTE type = item >> 12;        // 4 bits cao - loại relocation
            WORD offset = item & 0xFFF;    // 12 bits thấp - offset trong page
            
            // Chỉ xử lý relocation type HIGHLOW (phổ biến nhất)
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patchAddress = (DWORD*)((BYTE*)pImageBase + blockBase + offset);
                
                // Kiểm tra địa chỉ hợp lệ trước khi ghi
                if ((DWORD)patchAddress >= (DWORD)pImageBase && 
                    (DWORD)patchAddress <= (DWORD)pImageBase + pNtHeaders->OptionalHeader.SizeOfImage - sizeof(DWORD)) {
                    *patchAddress += delta;  // Áp dụng delta vào địa chỉ cần fixup
                    totalProcessed++;
                }
            }
            // Có thể thêm các loại relocation khác ở đây nếu cần
        }
        
        // Chuyển đến block tiếp theo
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }
    
    printf("[SUCCESS] Applied %d relocations\n", totalProcessed);
    return true;
}

// ============================================================================
// HÀM XỬ LÝ IMPORTS 
// ============================================================================

bool ProcessImports(LPVOID pImageBase, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD importRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    // Kiểm tra có import table không
    if (importRVA == 0) {
        printf("[INFO] No imports found\n");
        return true;
    }
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pImageBase + importRVA);
    DWORD dllCount = 0;
    DWORD funcCount = 0;
    
    printf("[INFO] Processing imports...\n");
    
    // Duyệt qua từng DLL trong import table (kết thúc bằng NULL)
    while (importDesc->Name != 0) {
        const char* dllName = (const char*)((BYTE*)pImageBase + importDesc->Name);
        printf("  Loading DLL: %s\n", dllName);
        
        // Load DLL vào memory
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            printf("[ERROR] Failed to load DLL: %s (Error: %d)\n", dllName, GetLastError());
            return false;
        }
        
        // OriginalFirstThunk (Import Lookup Table) hoặc FirstThunk (Import Address Table)
        PIMAGE_THUNK_DATA thunk = NULL;
        if (importDesc->OriginalFirstThunk != 0) {
            thunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + importDesc->OriginalFirstThunk);
        } else {
            thunk = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + importDesc->FirstThunk);
        }
            
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)pImageBase + importDesc->FirstThunk);
        
        // Duyệt qua từng hàm import trong DLL
        while (thunk->u1.AddressOfData != 0) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                // Import bằng ordinal
                UINT ordinal = IMAGE_ORDINAL32(thunk->u1.Ordinal);
                PROC func = (PROC)GetProcAddress(hModule, (LPCSTR)ordinal);
                if (!func) {
                    printf("[ERROR] Failed to get function by ordinal %d in %s\n", ordinal, dllName);
                    FreeLibrary(hModule);  // Giải phóng DLL trước khi thoát
                    return false;
                }
                iat->u1.Function = (DWORD)func;  // Ghi địa chỉ hàm vào IAT
                printf("    Ordinal %d -> 0x%08X\n", ordinal, func);
            } else {
                // Import bằng tên hàm
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pImageBase + thunk->u1.AddressOfData);
                PROC func = (PROC)GetProcAddress(hModule, (LPCSTR)importByName->Name);
                if (!func) {
                    printf("[ERROR] Failed to get function %s in %s\n", importByName->Name, dllName);
                    FreeLibrary(hModule);  // Giải phóng DLL trước khi thoát
                    return false;
                }
                iat->u1.Function = (DWORD)func;  // Ghi địa chỉ hàm vào IAT
                printf("    %s -> 0x%08X\n", importByName->Name, func);
            }
            funcCount++;
            thunk++;
            iat++;
        }
        
        dllCount++;
        importDesc++;  // Chuyển đến DLL tiếp theo
    }
    
    printf("[SUCCESS] Import resolution completed: %d DLLs, %d functions\n", dllCount, funcCount);
    return true;
}

// ============================================================================
// HÀM XỬ LÝ TLS CALLBACKS 
// ============================================================================

bool ExecuteTLSCallbacks(LPVOID pImageBase, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD tlsRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    
    // Kiểm tra có TLS directory không
    if (tlsRVA == 0) {
        printf("[INFO] No TLS Callbacks found\n");
        return true;
    }
    
    PIMAGE_TLS_DIRECTORY32 tlsDir = (PIMAGE_TLS_DIRECTORY32)((BYTE*)pImageBase + tlsRVA);
    PDWORD callbackArray = (PDWORD)tlsDir->AddressOfCallBacks;
    
    // Kiểm tra có callbacks không
    if (callbackArray == NULL || callbackArray == 0) {
        printf("[INFO] TLS Directory present but no callbacks\n");
        return true;
    }
    
    printf("[INFO] Executing TLS Callbacks...\n");
    DWORD callbackCount = 0;
    
    // Đăng ký exception handler (thay thế __try/__except)
    PVOID handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exception_filter);
    
    // Duyệt qua mảng callback (kết thúc bằng NULL)
    while (*callbackArray != 0 && *callbackArray != (DWORD)NULL) {
        // Định nghĩa con trỏ hàm TLS callback
        VOID (NTAPI *tlsCallback)(PVOID DllHandle, DWORD Reason, PVOID Reserved) = 
            (VOID (NTAPI *)(PVOID, DWORD, PVOID))(*callbackArray);
        
        if (tlsCallback) {
            printf("  Calling TLS Callback #%d at 0x%08X\n", callbackCount + 1, tlsCallback);
            
            // Sử dụng setjmp/longjmp để bắt exception (thay thế __try/__except)
            if (setjmp(env) == 0) {
                tlsCallback(pImageBase, DLL_PROCESS_ATTACH, NULL);
                callbackCount++;
            } else {
                printf("[WARNING] TLS Callback #%d caused exception\n", callbackCount + 1);
            }
        }
        
        callbackArray++;  // Chuyển đến callback tiếp theo
    }
    
    // Hủy đăng ký exception handler
    if (handler) {
        RemoveVectoredExceptionHandler(handler);
    }
    
    printf("[SUCCESS] Executed %d TLS Callbacks\n", callbackCount);
    return true;
}

// ============================================================================
// HÀM COPY SECTIONS (COMMENTS CHI TIẾT)
// ============================================================================

bool CopySections(LPVOID pFileBuffer, LPVOID pImageBase, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    
    printf("\n=== COPYING SECTIONS ===\n");
    printf("[INFO] Copying %d sections...\n", numberOfSections);
    
    // Copy PE headers
    DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    memcpy(pImageBase, pFileBuffer, sizeOfHeaders);
    
    // Copy từng section
    for (DWORD i = 0; i < numberOfSections; i++) {
        LPVOID dest = (BYTE*)pImageBase + sectionHeader[i].VirtualAddress;  // Địa chỉ đích trong memory
        DWORD rawSize = sectionHeader[i].SizeOfRawData;     // Kích thước trong file
        DWORD virtualSize = sectionHeader[i].Misc.VirtualSize; // Kích thước trong memory
        
        if (rawSize > 0) {
            LPVOID src = (BYTE*)pFileBuffer + sectionHeader[i].PointerToRawData;  // Địa chỉ nguồn trong file
            DWORD copySize = (rawSize < virtualSize) ? rawSize : virtualSize;  // Lấy kích thước nhỏ hơn
            memcpy(dest, src, copySize);
            
            // Zero-fill phần còn lại nếu virtualSize > rawSize (.bss = 0)
            if (virtualSize > copySize) {
                memset((BYTE*)dest + copySize, 0, virtualSize - copySize);
            }
        } else {
            // Section không có dữ liệu trong file, khởi tạo toàn bộ bằng 0
            memset(dest, 0, virtualSize);
        }
        
        // In chi tiết section
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
// HÀM SET PERMISSIONS
// ============================================================================

bool SetSectionPermissions(LPVOID pImageBase, PIMAGE_NT_HEADERS pNtHeaders) {
    DWORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    
    printf("[INFO] Setting section permissions...\n");
    
    for (DWORD i = 0; i < numberOfSections; i++) {
        DWORD protect = 0;
        BOOL executable = (sectionHeader[i].Characteristics & 0x20000000) != 0;  // IMAGE_SCN_MEM_EXECUTE
        BOOL writable = (sectionHeader[i].Characteristics & 0x80000000) != 0;    // IMAGE_SCN_MEM_WRITE  
        BOOL readable = (sectionHeader[i].Characteristics & 0x40000000) != 0;    // IMAGE_SCN_MEM_READ
        
        // Xác định permission dựa trên attributes của section
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
// HÀM VALIDATE FILE PATH
// ============================================================================

bool ValidateFilePath(const char* filePath) {
    // Kiểm tra độ dài đường dẫn
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
    size_t startIdx = (pathLen > 3) ? 3 : 0;   // không kiểm tra 3 ký tự đầu nếu có

    for (size_t i = startIdx; i < pathLen; i++) {
        for (size_t j = 0; j < strlen(invalidChars); j++) {
            if (filePath[i] == invalidChars[j]) {
                printf("[ERROR] File path contains invalid character: '%c' (pos %zu)\n", invalidChars[j], i);
                return false;
            }
        }
    }

    
    // Kiểm tra file có tồn tại không
    DWORD fileAttributes = GetFileAttributesA(filePath);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        printf("[ERROR] File does not exist or cannot be accessed: %s\n", filePath);
        return false;
    }
    
    // Kiểm tra có phải là directory không
    if (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        printf("[ERROR] Path is a directory, not a file: %s\n", filePath);
        return false;
    }
    
    // Kiểm tra extension .exe (cảnh báo nếu không phải)
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

// ============================================================================
// HÀM GET FILE PATH FROM USER
// ============================================================================

bool GetFilePathFromUser(char* filePath, int bufferSize) {
    printf("Please enter the path to the PE file (.exe):\n");
    printf("> ");
    
    // Sử dụng fgets để đọc cả dòng (hỗ trợ khoảng trắng)
    if (fgets(filePath, bufferSize, stdin) == NULL) {
        printf("[ERROR] Failed to read input\n");
        return false;
    }
    
    // Xóa ký tự newline ở cuối
    size_t len = strlen(filePath);
    if (len > 0 && filePath[len - 1] == '\n') {
        filePath[len - 1] = '\0';
    }
    
    // Kiểm tra nếu người dùng chỉ nhấn Enter
    if (strlen(filePath) == 0) {
        printf("[ERROR] No file path entered\n");
        return false;
    }
    
    // Xử lý đường dẫn có dấu ngoặc kép (người dùng có thể copy paste với quotes)
    if (filePath[0] == '\"' && filePath[len - 2] == '\"') {
        // Di chuyển các ký tự và remove quotes
        memmove(filePath, filePath + 1, len - 2);
        filePath[len - 2] = '\0';
    }
    
    return ValidateFilePath(filePath);
}


// Thong tin chung cua File
void DisplayFileInfo(const char* filePath, PIMAGE_NT_HEADERS pNtHeaders) {
    printf("\n=== FILE INFORMATION ===\n");
    printf("File: %s\n", filePath);
    printf("Architecture: %s\n", (pNtHeaders->FileHeader.Machine == 0x014C) ? "32-bit" : "Unknown");
    printf("Sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
    printf("Image Base: 0x%08X\n", pNtHeaders->OptionalHeader.ImageBase);
    printf("Entry Point: 0x%08X\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("Image Size: 0x%08X bytes\n", pNtHeaders->OptionalHeader.SizeOfImage);
}


// ============================================================================
// MAIN
// ============================================================================

int main() {
    printf("=== ADVANCED PE LOADER ===\n");
    printf("Supports: Relocations, TLS Callbacks, Import Resolution\n\n");
    
    // Khởi tạo các biến resource
    char peFilePath[MAX_PATH] = {0};
    LPVOID pFileBuffer = NULL;
    HANDLE hMapping = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPVOID pImageBase = NULL;
    
    // code fix cứng const char* peFilePath = "L:/NCSS Malware Analyze/Bai 2.1 va 2.2/check_subdir.exe";    //change dir
    
    // Nhận đường dẫn từ người dùng
    if (!GetFilePathFromUser(peFilePath, sizeof(peFilePath))) {
        printf("[ERROR] Invalid file path\n");
        return 1;
    }


    // Mở file PE
    hFile = CreateFileA(peFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Cannot open file: %s (Error: %d)\n", peFilePath, GetLastError());
        return 1;
    }
    
    // Lấy kích thước file
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[ERROR] Invalid file size\n");
        CleanupResources(NULL, NULL, NULL, hFile);
        return 1;
    }
    
    // Tạo file mapping
    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        printf("[ERROR] CreateFileMapping failed (Error: %d)\n", GetLastError());
        CleanupResources(NULL, NULL, NULL, hFile);
        return 1;
    }
    
    // Map file vào memory
    pFileBuffer = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, fileSize);
    if (!pFileBuffer) {
        printf("[ERROR] MapViewOfFile failed (Error: %d)\n", GetLastError());
        CleanupResources(NULL, NULL, hMapping, hFile);
        return 1;
    }
    
    printf("[SUCCESS] File mapped at 0x%p, size: 0x%08X bytes\n", pFileBuffer, fileSize);
    
    // Parse PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDosHeader->e_magic != 0x5A4D) {  // "MZ"
        printf("[ERROR] Not a valid DOS executable\n");
        CleanupResources(NULL, pFileBuffer, hMapping, hFile);
        return 1;
    }
    
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
    
    // Validate cấu trúc PE
    if (!ValidatePE(pDosHeader, pNtHeaders, fileSize)) {
        CleanupResources(NULL, pFileBuffer, hMapping, hFile);
        return 1;
    }

    // In thông tin tổng quan File
    DisplayFileInfo(peFilePath, pNtHeaders);
    
    // Cấp phát bộ nhớ cho PE image
    DWORD imageBase = pNtHeaders->OptionalHeader.ImageBase;
    DWORD sizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    DWORD entryPointRVA = pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    
    printf("[INFO] Preferred base: 0x%08X, Image size: 0x%08X, Entry point: 0x%08X\n", 
           imageBase, sizeOfImage, entryPointRVA);
    
    // Thử cấp phát tại base address mong muốn
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
    
    printf("[SUCCESS] Image allocated at 0x%p\n", pImageBase);


     // Xác định có cần relocate không
    BOOL needRelocate = (pImageBase != (LPVOID)imageBase);
    if (needRelocate) {
        printf("[INFO] Image not allocated at preferred base -> relocations required\n");
    } else {
        printf("[INFO] Image allocated at preferred base -> relocations NOT required\n");
    }

    
    // Thực hiện các bước load PE với exception handling
    bool success = false;
    PVOID main_handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exception_filter);
    
    // Sử dụng setjmp/longjmp để bắt exception (thay thế __try/__finally)
    if (setjmp(env) == 0) {
        // Copy sections từ file vào memory
        if (!CopySections(pFileBuffer, pImageBase, pNtHeaders)) {
            printf("[ERROR] Failed to copy sections\n");
            success = false;
        }
        // Xử lý relocation (fixup địa chỉ)
        else if (!ProcessRelocations(pImageBase, pNtHeaders)) {
            printf("[ERROR] Relocation failed\n");
            success = false;
        }
        // Resolve import functions (load DLLs, get function addresses)
        else if (!ProcessImports(pImageBase, pNtHeaders)) {
            printf("[ERROR] Import resolution failed\n");
            success = false;
        }
        // Gọi TLS Callbacks (QUAN TRỌNG: trước entry point)
        else if (!ExecuteTLSCallbacks(pImageBase, pNtHeaders)) {
            printf("[ERROR] TLS Callbacks execution failed\n");
            success = false;
        }
        // Set memory protections (RX, RW, RO cho từng section)
        else if (!SetSectionPermissions(pImageBase, pNtHeaders)) {
            printf("[WARNING] Section permission setting had issues\n");
            success = true; // Vẫn tiếp tục dù có warning
        } else {
            success = true;
        }
    } else {
        printf("[ERROR] Exception occurred during PE loading\n");
        success = false;
    }
    
    // Hủy đăng ký exception handler
    if (main_handler) {
        RemoveVectoredExceptionHandler(main_handler);
    }
    
    // Nếu có lỗi, cleanup ngay lập tức
    if (!success) {
        CleanupResources(pImageBase, pFileBuffer, hMapping, hFile);
        return 1;
    }
    
    // Cảnh báo nếu target là DLL
    if (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        printf("[WARNING] Target file has IMAGE_FILE_DLL flag set — entry behaviour may differ.\n");
    }

    // Chuẩn bị execute file exe trong dir
    printf("\n=== READY TO EXECUTE ===\n");
    printf("Entry Point: 0x%p\n", (BYTE*)pImageBase + entryPointRVA);
    printf("Press:\n");
    printf("  1 - Execute program\n");
    printf("  2 - Exit without execution\n");
    
    int choice = getchar();
    // Xóa buffer input
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    if (choice == '1') {
        printf("\n[EXECUTING] Transferring control to entry point...\n");
        
        // Đăng ký exception handler cho quá trình execution
        PVOID exec_handler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)exception_filter);
        
        // Thực thi entry point với exception handling
        if (setjmp(env) == 0) {
            void (*entryPoint)() = (void(*)())((BYTE*)pImageBase + entryPointRVA);
            entryPoint();  // Gọi entry point của chương trình
            printf("[INFO] Program execution completed normally\n");
        } else {
            printf("[EXCEPTION] Program caused exception during execution\n");
        }
        
        // Hủy đăng ký exception handler
        if (exec_handler) {
            RemoveVectoredExceptionHandler(exec_handler);
        }
    } else {
        printf("[INFO] Execution cancelled by user\n");
    }
    
    // Dọn dẹp tài nguyên sau khi chạy
    CleanupResources(pImageBase, pFileBuffer, hMapping, hFile);
    
    printf("Press Enter to exit...\n");
    getchar(); getchar();
    
    return 0;
}