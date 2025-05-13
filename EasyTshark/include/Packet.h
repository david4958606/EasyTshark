#pragma once
import <string>;
import <vector>;


struct Packet
{
    // -e frame.number -e frame.time -e ip.src -e ipv6.src
    // -e tcp.srcport -e udp.srcport -e ip.dst -e ipv6.dst
    // -e tcp.dstport -e udp.dstport
    // -e _ws.col.Protocol -e _ws.col.Info
    int         FrameNumber;
    std::string Time;
    uint32_t    CapLen;
    std::string SourceIp;
    int         SourcePort;
    std::string DestinationIp;
    int         DestinationPort;
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

void ParseLine(std::string line, Packet& packet);
void PrintPacket(const Packet& packet);
void ReadPcap(const std::string& path);
bool ReadPacketHex(const std::string& filePath, uint32_t offset, uint32_t length, std::vector<unsigned char>& buffer);
