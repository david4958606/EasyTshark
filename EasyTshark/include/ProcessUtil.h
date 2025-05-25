#pragma once

#include <string>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/types.h>
using PidT = pid_t;
#elif defined(_WIN32)
#include <Windows.h>
using PidT = DWORD;
#endif

namespace ProcessUtil
{
    FILE* PopenEx(std::string command, PidT* pidOut = nullptr);
    int   Kill(PidT pid);
    bool  Exec(std::string cmdLine);
}
