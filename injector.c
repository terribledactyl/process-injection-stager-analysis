#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int main() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (lstrcmpi(pe32.szExeFile, "explorer.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (pid == 0) {
        printf("Target process not found.\n");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("Could not open target process.\n");
        return 1;
    }

    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuffer) {
        printf("Memory allocation failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    const char* message = "Hello from injected code!";
    SIZE_T written;
    WriteProcessMemory(hProcess, remoteBuffer, message, strlen(message) + 1, &written);

    printf("Wrote %zu bytes into remote process memory.\n", written);

    CloseHandle(hProcess);
    return 0;
}
