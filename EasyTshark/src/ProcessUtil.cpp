#include "ProcessUtil.h"

#if defined(__unix__) || defined(__APPLE__)
#include <cstdlib>
#include <unistd.h>
#include <csignal>
#include <sys/wait.h>

namespace ProcessUtil {

    FILE* PopenEx(std::string command, PidT* pidOut) {
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            perror("pipe");
            return nullptr;
        }

        PidT pid = fork();
        if (pid == -1) {
            perror("fork");
            close(pipefd[0]);
            close(pipefd[1]);
            return nullptr;
        }
        else if (pid == 0) {
            // Child process
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);
            execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
            perror("execl");
            _exit(1);
        }
        else {
            // Parent
            close(pipefd[1]);
            FILE* fp = fdopen(pipefd[0], "r");
            if (pidOut) *pidOut = pid;
            return fp;
        }
    }

    int Kill(PidT pid) {
        return kill(pid, SIGTERM);
    }

} // namespace ProcessUtil

#elif defined(_WIN32)
#include <process.h>
#include <corecrt_io.h>
#include <fcntl.h>
#include <iostream>

namespace ProcessUtil
{
    FILE* PopenEx(std::string command, PidT* pidOut)
    {
        HANDLE              hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES saAttr;
        PROCESS_INFORMATION piProcInfo;
        STARTUPINFOA        siStartInfo;

        saAttr.nLength              = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle       = TRUE;
        saAttr.lpSecurityDescriptor = nullptr;

        if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0))
        {
            perror("CreatePipe");
            return nullptr;
        }

        if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0))
        {
            perror("SetHandleInformation");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }

        ZeroMemory(&siStartInfo, sizeof(siStartInfo));
        ZeroMemory(&piProcInfo, sizeof(piProcInfo));
        siStartInfo.cb         = sizeof(siStartInfo);
        siStartInfo.hStdOutput = hWritePipe;
        siStartInfo.hStdError  = hWritePipe;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        if (!CreateProcessA(
            nullptr,
            command.data(),
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &siStartInfo,
            &piProcInfo))
        {
            perror("CreateProcessA");
            CloseHandle(hReadPipe);
            CloseHandle(hWritePipe);
            return nullptr;
        }

        CloseHandle(hWritePipe);
        if (pidOut) *pidOut = piProcInfo.dwProcessId;

        FILE* fp = _fdopen(_open_osfhandle(reinterpret_cast<intptr_t>(hReadPipe), _O_RDONLY), "r");
        if (!fp) CloseHandle(hReadPipe);

        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
        return fp;
    }

    int Kill(PidT pid)
    {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess)
        {
            std::cout << "Failed to open process " << pid << ", error: " << GetLastError() << std::endl;
            return -1;
        }

        if (!TerminateProcess(hProcess, 0))
        {
            std::cout << "Failed to terminate process " << pid << ", error: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return -1;
        }

        CloseHandle(hProcess);
        return 0;
    }
} // namespace ProcessUtil
#endif
