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
