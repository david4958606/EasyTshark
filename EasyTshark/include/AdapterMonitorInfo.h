#pragma once
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "ProcessUtil.h"

class AdapterMonitorInfo
{
public:
    AdapterMonitorInfo()
    {
        MonitorTsharkPipe = nullptr;
        TsharkPid         = 0;
    }

    std::string                  AdapterName;
    std::map<long, long>         FlowTrendData; // <time, bytes>
    std::shared_ptr<std::thread> MonitorThread;
    FILE*                        MonitorTsharkPipe;
    PidT                         TsharkPid;
};
