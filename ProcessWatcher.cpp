#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <string>
#include <set>

void logEvent(const std::wstring& event, std::wofstream& logfile) {
    std::wcout << event << std::endl;
    logfile << event << std::endl;
}

void printColored(const std::wstring& message, WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
    std::wcout << message << std::endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

int main() {
    // Open logfile for writing
    std::wofstream logfile("application_log.txt");
    if (!logfile.is_open()) {
        std::wcerr << L"Error opening logfile." << std::endl;
        return 1;
    }

    // Log start of the program
    logEvent(L"Program started.", logfile);

    // Set to store the previously detected processes
    std::set<std::wstring> prevProcesses;

    // Main loop to monitor running processes
    while (true) {
        // Get list of processes
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        std::set<std::wstring> currentProcesses;

        if (Process32FirstW(snapshot, &entry) == TRUE) {
            do {
                // Convert WCHAR to std::wstring
                std::wstring processName(entry.szExeFile);

                // Log the process name
                currentProcesses.insert(processName);
            } while (Process32NextW(snapshot, &entry) == TRUE);
        }

        // Close handle
        CloseHandle(snapshot);

        // Compare current processes with previous ones
        for (const auto& process : currentProcesses) {
            if (prevProcesses.find(process) == prevProcesses.end()) {
                // New process detected
                printColored(L"[+] Detected new running process: " + process, FOREGROUND_GREEN);
            }
        }

        for (const auto& process : prevProcesses) {
            if (currentProcesses.find(process) == currentProcesses.end()) {
                // Stopped process detected
                printColored(L"[-] Detected stopped process: " + process, FOREGROUND_RED);
            }
        }

        // Update previous processes set
        prevProcesses = std::move(currentProcesses);

        // Wait before checking again
        Sleep(5000); // Wait for 5 seconds before checking again
    }

    // Log end of the program (This line will never be reached)
    logEvent(L"Program ended.", logfile);

    // Close logfile
    logfile.close();

    return 0;
}
