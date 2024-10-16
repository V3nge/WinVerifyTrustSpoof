#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD GetProcID(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &processEntry)) {
            do {
                if (processName == processEntry.szExeFile) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }

    return processId;
}

int main(int argc, wchar_t* argv[])
{
    const wchar_t* procName = L"TrustCheck.exe"; // application name
    DWORD procID = GetProcID(procName);
    std::cout << procID;

    const HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
    
    const HMODULE WintrustModule = LoadLibrary(L"wintrust.dll");
    const FARPROC WinVerifyTrustAddress = GetProcAddress(WintrustModule, "WinVerifyTrust");

    /*
    0:  48 31 c0                xor    rax,rax
    3:  59                      pop    rcx
    4:  ff e1                   jmp    rcx
    */
    char Shellcode[6] = { 0x48, 0x31, 0xC0, 0x59, 0xFF, 0xE1 };

    DWORD oldProtection;
    VirtualProtectEx(procHandle, WinVerifyTrustAddress, sizeof(Shellcode), PAGE_EXECUTE_READWRITE, &oldProtection);

    SIZE_T bytes;
    WriteProcessMemory(procHandle, WinVerifyTrustAddress, Shellcode, sizeof(Shellcode), &bytes);

    VirtualProtectEx(procHandle, WinVerifyTrustAddress, sizeof(Shellcode), PAGE_EXECUTE_READ, &oldProtection);

    return 0;
}