#pragma once

#if defined(__unix__) || defined(__APPLE__)
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <string>
#endif
#ifdef _WIN32
import <cstdio>;
import <vector>;
import <Windows.h>;
import <string>;
import <process.h>;
import <corecrt_io.h>;
import <fcntl.h>;
import <iostream>;
#endif


#ifdef _WIN32
typedef DWORD PidT;
#else
typedef pid_t PidT;
#endif

class ProcessUtil
{
public:
#if defined(__unix__) || defined(__APPLE__)
    static FILE* PopenEx(std::string command, PidT* pidOut = nullptr)
    {
        int   pipefd[2] = { 0 };
        FILE* pipeFp    = nullptr;

        if (pipe(pipefd) == -1)
        {
            perror("pipe");
            return nullptr;
        }
        PidT pid = fork();
        if (pid == -1)
        {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            return nullptr;
        }
        else if (pid == 0) // Child process
        {
            close(pipefd[0]);               // Close read end of the pipe in child
            dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe
            dup2(pipefd[1], STDERR_FILENO); // Redirect stderr to pipe
            close(pipefd[1]);               // Close write end of the pipe in child
            execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
            perror("execl"); // If execl fails, print error message
            _exit(1);         // Exit child process with error code
        }
        else // Parent process
        {
            close(pipefd[1]); // Close write end of the pipe in parent
            pipeFp = fdopen(pipefd[0], "r"); // Open read end of the pipe as a FILE*
            if (pidOut != nullptr)
                *pidOut = pid; // Store the child process ID if requested
        }
        return pipeFp; // Return the FILE* for reading from the pipe
    }
#endif

#ifdef _WIN32
    static FILE* PopenEx(std::string command, PidT* pidOut = nullptr)
    {
        HANDLE              hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES saAttr;
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFOA        siStartInfo;
        FILE*               pipeFp = nullptr;

        saAttr.nLength              = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle       = TRUE;
        saAttr.lpSecurityDescriptor = nullptr;

        // Create an anonymous pipe for STDOUT
        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
        {
            perror("CreatePipe");
            return nullptr;
        }

        // Make sure the read handle to the pipe for STDOUT is not inherited
        if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
        {
            perror("SetHandleInformation");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }

        // Init StartupInfo structure
        ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
        siStartInfo.cb         = sizeof(STARTUPINFOA);
        siStartInfo.hStdOutput = hWritePipe;         // Redirect STDOUT to the write end of the pipe
        siStartInfo.hStdError  = hWritePipe;         // Redirect STDERR to the write end of the pipe
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES; // Use the standard handles

        // Create the child process
        if (!CreateProcessA(
            nullptr,          // No module name (use command line)
            command.data(),   // Command line
            nullptr,          // Process handle not inheritable
            nullptr,          // Thread handle not inheritable
            TRUE,             // Set handle inheritance to TRUE
            CREATE_NO_WINDOW, // No window
            nullptr,          // Use parent's environment block
            nullptr,          // Use parent's starting directory
            &siStartInfo,     // Pointer to STARTUP INFO structure
            &piProcInfo       // Pointer to PROCESS_INFORMATION structure
        ))
        {
            perror("CreateProcessA");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }

        // Close unused handles
        CloseHandle(hWritePipe);
        // Return child process ID if requested
        if (pidOut)
        {
            *pidOut = piProcInfo.dwProcessId;
        }

        // Open the read end of the pipe as a FILE*
        pipeFp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
        if (!pipeFp)
        {
            CloseHandle(hReadPipe);
        }

        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        return pipeFp;
    }
#endif

#if defined(__unix__) || defined(__APPLE__)
    static int Kill(PID_T pid) {
        return kill(pid, SIGTERM);
    }
#endif

#ifdef _WIN32
    static int Kill(const PidT pid)
    {
        // 打开指定进程
        const HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == nullptr)
        {
            std::cout << "Failed to open process with PID " << pid << ", error: " << GetLastError() << std::endl;
            return -1;
        }

        // 终止进程
        if (!TerminateProcess(hProcess, 0))
        {
            std::cout << "Failed to terminate process with PID " << pid << ", error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        // 成功终止进程
        CloseHandle(hProcess);
        return 0;
    }
#endif
};
