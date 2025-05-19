#pragma once
import <string>;
import <thread>;
import <unordered_map>;

#include "document.h"
#include "Ip2RegionUtil.h"
#include "TsharkDataType.h"


#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

class TsharkManager
{
public:
    explicit TsharkManager(const std::string& workDir);
    ~TsharkManager();

    // analyze pcap file
    bool ReadPcap(const std::string& path);

    void PrintAllPackets() const;

    bool ReadPacketHex(uint32_t frameNumber, std::vector<unsigned char>& data);

    std::vector<AdapterInfo> GetNetworkAdapters();

    bool StartCapture(const std::string& adapterName);

    bool StopCapture();

private:
    static bool ParseLine(std::string line, const std::shared_ptr<Packet>& packet);

    static std::string ConvertTimeStamp(const std::string& timestampStr);

    std::string TsharkPath;

    std::string CurrentFilePath;

    Ip2RegionUtil& IpUtil = Ip2RegionUtil::Instance();

    std::unordered_map<uint32_t, std::shared_ptr<Packet>> AllPackets;

    void CaptureWorkThreadEntry(const std::string& adapterName);

    std::shared_ptr<std::thread> CaptureWorkThread;

    bool StopFlag;
};

typedef rapidjson::Document::AllocatorType& AllocatorType;
