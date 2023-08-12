#include "windows.h"
#include <vector>
#include <iostream>
#include <fstream>


const unsigned char* GetFileBytes(const wchar_t* fileName, DWORD* byteRead) {
    HANDLE hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return nullptr;
    }
    const unsigned char* outBuffer = new unsigned char[fileSize];
    if (!ReadFile(hFile, (LPVOID)outBuffer, fileSize, byteRead, NULL)) {
        CloseHandle(hFile);
        delete[] outBuffer;
        return nullptr;
    }
    CloseHandle(hFile);
    return outBuffer;
}



PVOID GetExedAllocation(const unsigned char* Buffer, SIZE_T size) {
    PVOID allocation = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (allocation == NULL) {
        return NULL;
    }
    CopyMemory(allocation, Buffer, size);
    return allocation;
}


void GetHeaders(PVOID pexeFile, PIMAGE_DOS_HEADER* pDOSHeader, PIMAGE_NT_HEADERS64* pNTHeaders) {
    *pDOSHeader = (PIMAGE_DOS_HEADER)pexeFile;
    *pNTHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)pexeFile + (*pDOSHeader)->e_lfanew);
}

PVOID GetFixedBaseAddress(PIMAGE_NT_HEADERS64 pNTHeaders) {
    std::cout << "Size Of image: " << std::hex << pNTHeaders->OptionalHeader.SizeOfImage << "\n";

    return VirtualAlloc(0, pNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void WriteHeaders(PVOID pExeFile, PVOID baseAddress, PIMAGE_NT_HEADERS64 pNTHeaders) {
    std::cout << "Size of headers: " << std::hex << pNTHeaders->OptionalHeader.SizeOfHeaders << "\n";
    memcpy(baseAddress, pExeFile, pNTHeaders->OptionalHeader.SizeOfHeaders);
}


bool FixImports(PIMAGE_NT_HEADERS64 pNTHeaders, PVOID baseAdress) {
    if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PVOID importPtr = (PVOID)((LPBYTE)baseAdress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        while (ImportDesc.Name != 0) {
            char* dllName = (char*)((PVOID)((LPBYTE)baseAdress + ImportDesc.Name));
            std::string dllNameStr(dllName);
            std::cout << "\nLoading: " << dllNameStr << "\n";
            HMODULE Dllh = LoadLibraryA(dllNameStr.c_str());
            if (!Dllh) {
                DWORD error = GetLastError();
                std::cerr << "Failed to load the DLL. Error code: " << error << "\n";
                return FALSE;
            }
            PVOID pOft = (PVOID)((LPBYTE)baseAdress + ImportDesc.OriginalFirstThunk);
            PVOID pfirstthunk = (PVOID)((LPBYTE)baseAdress + ImportDesc.FirstThunk);
            IMAGE_THUNK_DATA64 thunk = *(IMAGE_THUNK_DATA64*)pOft;
            while (thunk.u1.Function < 0x8000000000000000 && thunk.u1.Function != 0) {
                LPBYTE pNameAddress = (LPBYTE)baseAdress + thunk.u1.AddressOfData;
                char* funcName = (char*)(pNameAddress + 2);
                std::string funcNamestr(funcName);
                std::cout << "  Function name: " << funcNamestr << "\n";
                FARPROC functionAddress = GetProcAddress(Dllh, funcName);
                if (functionAddress) {
                    std::cout << "      Function Address: " << std::hex << functionAddress << "\n";
                    *(FARPROC*)pfirstthunk = functionAddress;
                }
                else {
                    return FALSE;
                }
                pfirstthunk = (PVOID)(((LPBYTE)pfirstthunk) + 8);
                pOft = (PVOID)(((LPBYTE)pOft) + sizeof(IMAGE_THUNK_DATA64));
                thunk = *(IMAGE_THUNK_DATA64*)pOft;
            }

            importPtr = (PVOID)((LPBYTE)importPtr + sizeof(IMAGE_IMPORT_DESCRIPTOR));
            ImportDesc = *(IMAGE_IMPORT_DESCRIPTOR*)importPtr;
        }
    }
    return TRUE;
}



void WriteSections(PVOID baseAdress, PVOID pExeFile, PIMAGE_DOS_HEADER pDOSHeader, PIMAGE_NT_HEADERS64 pNTHeaders) {

    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSectionHeader =
            (PIMAGE_SECTION_HEADER)((LPBYTE)baseAdress + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)
                + (i * sizeof(IMAGE_SECTION_HEADER)));

        std::cout << pSectionHeader->Name << "\n";
        std::cout << "Virtual Address: " << std::hex << pSectionHeader->VirtualAddress << "\n";
        std::cout << "Raw offset: " << std::hex << pSectionHeader->PointerToRawData << "\n";
        std::cout << "Size of raw data: " << std::hex << pSectionHeader->SizeOfRawData << "\n";
        std::cout << "Virtual Size: " << std::hex << pSectionHeader->Misc.VirtualSize << "\n";
        if (pSectionHeader->SizeOfRawData > 0) {
            std::cout << "Writing section to: " << std::hex << (PVOID)((LPBYTE)baseAdress + pSectionHeader->VirtualAddress) << "\n";
            memcpy((PVOID)((LPBYTE)baseAdress + pSectionHeader->VirtualAddress),
                (PVOID)((LPBYTE)pExeFile + pSectionHeader->PointerToRawData),
                pSectionHeader->SizeOfRawData);

        }
        std::cout << "\n";
    }
}
void BaseRelocation(PVOID baseAdress, PIMAGE_NT_HEADERS64 pNTHeaders) {
    LONG64 delta = (LONG64)baseAdress - (LONG64)pNTHeaders->OptionalHeader.ImageBase;

    std::cout << "Expected ImageBase: " << std::hex << pNTHeaders->OptionalHeader.ImageBase << "\n";
    std::cout << "Loaded ImageBase: " << std::hex << baseAdress << "\n";
    std::cout << "Delta: " << std::hex << delta << "\n";

    PVOID pFirstReloc = (PVOID)((LPBYTE)baseAdress + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD allRelocSize = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    IMAGE_BASE_RELOCATION reloc = *(IMAGE_BASE_RELOCATION*)pFirstReloc;

    while (reloc.SizeOfBlock != 0)
    {
        std::cout << "reloc...\n";

        int entries = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        WORD* pOffset = (WORD*)((IMAGE_BASE_RELOCATION*)pFirstReloc + 1);

        for (int i = 0; i < entries; i++, pOffset++)
        {
            WORD type = *pOffset >> 12;
            WORD offset = *pOffset & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64)
            {
                LONG64* pAddressToPatch = (LONG64*)((LPBYTE)baseAdress + reloc.VirtualAddress + offset);
                *pAddressToPatch += delta;
            }
        }

        pFirstReloc = (PVOID)((LPBYTE)pFirstReloc + reloc.SizeOfBlock);
        reloc = *(IMAGE_BASE_RELOCATION*)pFirstReloc;
    }
}

bool LoadAndExecute(const wchar_t* fileName) {
    DWORD fileSize;
    const unsigned char* rawFile = GetFileBytes(fileName, &fileSize);

    if (!rawFile) {
        std::cerr << "Unable to read file content." << "\n";
        return false;
    }

    PVOID pExeFile = GetExedAllocation(rawFile, fileSize);
    if (!pExeFile) {
        std::cerr << "Unable to allocate memory." << "\n";
        delete[] rawFile;
        return false;
    }

    PIMAGE_DOS_HEADER pDOSHeader;
    PIMAGE_NT_HEADERS64 pNTHeaders;
    GetHeaders(pExeFile, &pDOSHeader, &pNTHeaders);

    PVOID baseAddress = GetFixedBaseAddress(pNTHeaders);
    if (!baseAddress) {
        std::cerr << "Unable to allocate base address." << "\n";
        delete[] rawFile;
        VirtualFree(pExeFile, 0, MEM_RELEASE);
        return false;
    }

    WriteHeaders(pExeFile, baseAddress, pNTHeaders);
    WriteSections(baseAddress, pExeFile, pDOSHeader, pNTHeaders);

    if (!FixImports(pNTHeaders, baseAddress)) {
        std::cerr << "Failed to fix imports." << "\n";
        delete[] rawFile;
        VirtualFree(pExeFile, 0, MEM_RELEASE);
        VirtualFree(baseAddress, 0, MEM_RELEASE);
        return false;
    }

    BaseRelocation(baseAddress, pNTHeaders);

    DWORD threadID;
    HANDLE threadHandle = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((LPBYTE)baseAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint),
        NULL,
        0,
        &threadID
    );

    if (!threadHandle) {
        std::cerr << "Error occurred during thread creation!" << "\n";
        delete[] rawFile;
        VirtualFree(pExeFile, 0, MEM_RELEASE);
        VirtualFree(baseAddress, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(threadHandle, INFINITE);
    CloseHandle(threadHandle);

    delete[] rawFile;
    VirtualFree(pExeFile, 0, MEM_RELEASE);
    VirtualFree(baseAddress, 0, MEM_RELEASE);

    return true;
}

int main() {
    const wchar_t* fileName = L"< Exe Path >";
    if (!LoadAndExecute(fileName)) {
        return 1;
    }
    return 0;
}
