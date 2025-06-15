#pragma once
import <iostream>;
import <cstdio>;
import <cstdlib>;
import <cstring>;
import <vector>;

struct Packet
{
    int         FrameNumber;
    std::string Time;
    std::string SourceMac;
    std::string DestinationMac;
    uint32_t    CapLen;
    uint32_t    Len;
    std::string SourceIp;
    std::string SourceLocation;
    uint16_t    SourcePort;
    std::string DestinationIp;
    std::string DestinationLocation;
    uint16_t    DestinationPort;
    std::string Protocol;
    std::string Info;
    uint32_t    FileOffset;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const
    {
        rapidjson::Value pktObj(rapidjson::kObjectType);
        obj.AddMember("frame_number", FrameNumber, allocator);
        obj.AddMember("timestamp", rapidjson::Value(Time.c_str(), allocator), allocator);
        obj.AddMember("src_mac", rapidjson::Value(SourceMac.c_str(), allocator), allocator);
        obj.AddMember("dst_mac", rapidjson::Value(DestinationMac.c_str(), allocator), allocator);
        obj.AddMember("src_ip", rapidjson::Value(SourceIp.c_str(), allocator), allocator);
        obj.AddMember("src_location", rapidjson::Value(SourceLocation.c_str(), allocator), allocator);
        obj.AddMember("src_port", SourcePort, allocator);
        obj.AddMember("dst_ip", rapidjson::Value(DestinationIp.c_str(), allocator), allocator);
        obj.AddMember("dst_location", rapidjson::Value(DestinationLocation.c_str(), allocator), allocator);
        obj.AddMember("dst_port", DestinationPort, allocator);
        obj.AddMember("len", Len, allocator);
        obj.AddMember("cap_len", CapLen, allocator);
        obj.AddMember("protocol", rapidjson::Value(Protocol.c_str(), allocator), allocator);
        obj.AddMember("info", rapidjson::Value(Info.c_str(), allocator), allocator);
        obj.AddMember("file_offset", FileOffset, allocator);
    }
};


// PCAP Global Header
struct PcapHeader
{
    uint32_t MagicNumber;  // 4 bytes D4 C3 B2 A1
    uint16_t VersionMajor; // 2 bytes 02 00
    uint16_t VersionMinor; // 2 bytes 04 00
    int32_t  ThisZone;     // 4 bytes 00 00 04 00
    uint32_t SigFigs;      // 4 bytes 01 00 00 00
    uint32_t SnapLen;      // 4 bytes 41 02 00 00
    uint32_t Network;      // 4 bytes 41 02 00 00
};

// PCAP Packet Header
struct PacketHeader
{
    uint32_t TsSec;
    uint32_t TsUSec;
    uint32_t CapLen;
    uint32_t Len;
};

// Network Adapter
struct AdapterInfo
{
    int         Id;
    std::string Name;
    std::string Remark;
};
