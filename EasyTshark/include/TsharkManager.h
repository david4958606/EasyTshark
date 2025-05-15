#pragma once
import <string>;
import <unordered_map>;

#include "document.h"
#include "Ip2RegionUtil.h"
#include "TsharkDataType.h"


class TsharkManager
{
public:
    explicit TsharkManager(const std::string& workDir);
    ~TsharkManager();

    // analyze pcap file
    bool ReadPcap(const std::string& path);

    void PrintAllPackets() const;

    bool ReadPacketHex(uint32_t frameNumber, std::vector<unsigned char>& data);

private:
    static bool ParseLine(std::string line, const std::shared_ptr<Packet>& packet);

    std::string TsharkPath;

    std::string CurrentFilePath;

    Ip2RegionUtil& IpUtil = Ip2RegionUtil::Instance();

    std::unordered_map<uint32_t, std::shared_ptr<Packet>> AllPackets;
};

typedef rapidjson::Document::AllocatorType& AllocatorType;
