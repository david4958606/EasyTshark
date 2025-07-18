#pragma once
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <vector>

#include "MiscUtil.h"

struct BaseDataObject
{
protected:
    ~BaseDataObject() = default;

public:
    // 将对象转换为JSON Value，用于转换为JSON格式输出
    virtual void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const = 0;
};

struct Packet final : BaseDataObject
{
    virtual     ~Packet() = default;
    int         FrameNumber;
    double      Time;
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
    std::string TransProtocol;
    std::string Protocol;
    std::string Info;
    uint32_t    FileOffset;
    uint32_t    BelongSessionId;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        rapidjson::Value pktObj(rapidjson::kObjectType);
        obj.AddMember("frame_number", FrameNumber, allocator);
        obj.AddMember("timestamp", Time, allocator);
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
        obj.AddMember("trans_protocol", rapidjson::Value(TransProtocol.c_str(), allocator), allocator);
        obj.AddMember("protocol", rapidjson::Value(Protocol.c_str(), allocator), allocator);
        obj.AddMember("info", rapidjson::Value(Info.c_str(), allocator), allocator);
        obj.AddMember("file_offset", FileOffset, allocator);
        obj.AddMember("belong_session_id", BelongSessionId, allocator);
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

struct Session final : BaseDataObject
{
    virtual     ~Session() = default;
    uint32_t    SessionId;
    std::string Ip1;
    uint16_t    Ip1Port;
    std::string Ip1Location;
    std::string Ip2;
    uint16_t    Ip2Port;
    std::string Ip2Location;
    std::string TransProtocol;
    std::string AppProtocol;
    double      StartTime;
    double      EndTime;
    uint32_t    Ip1SendPacketCount;
    uint32_t    Ip1SendBytesCount;
    uint32_t    Ip2SendPacketCount;
    uint32_t    Ip2SendBytesCount;
    uint32_t    PacketCount;
    uint32_t    TotalBytes;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        rapidjson::Value sessionObj(rapidjson::kObjectType);
        obj.AddMember("session_id", SessionId, allocator);
        obj.AddMember("ip1", rapidjson::Value(Ip1.c_str(), allocator), allocator);
        obj.AddMember("ip1_port", Ip1Port, allocator);
        obj.AddMember("ip1_location", rapidjson::Value(Ip1Location.c_str(), allocator), allocator);
        obj.AddMember("ip2", rapidjson::Value(Ip2.c_str(), allocator), allocator);
        obj.AddMember("ip2_port", Ip2Port, allocator);
        obj.AddMember("ip2_location", rapidjson::Value(Ip2Location.c_str(), allocator), allocator);
        obj.AddMember("trans_protocol", rapidjson::Value(TransProtocol.c_str(), allocator), allocator);
        obj.AddMember("app_protocol", rapidjson::Value(AppProtocol.c_str(), allocator), allocator);
        obj.AddMember("start_time", StartTime, allocator);
        obj.AddMember("end_time", EndTime, allocator);
        obj.AddMember("ip1_send_packet_count", Ip1SendPacketCount, allocator);
        obj.AddMember("ip1_send_bytes_count", Ip1SendBytesCount, allocator);
        obj.AddMember("ip2_send_packet_count", Ip2SendPacketCount, allocator);
        obj.AddMember("ip2_send_bytes_count", Ip2SendBytesCount, allocator);
        obj.AddMember("packet_count", PacketCount, allocator);
        obj.AddMember("bytes_count", TotalBytes, allocator);
    }
};

struct FiveTuple
{
    std::string SrcIp;
    std::string DstIp;
    uint16_t    SrcPort;
    uint16_t    DstPort;
    std::string TransProto;

    bool operator==(const FiveTuple& other) const
    {
        if (TransProto != other.TransProto)
            return false;

        const bool sameDirection =
            SrcIp == other.SrcIp &&
            DstIp == other.DstIp &&
            SrcPort == other.SrcPort &&
            DstPort == other.DstPort;

        const bool reverseDirection =
            SrcIp == other.DstIp &&
            DstIp == other.SrcIp &&
            SrcPort == other.DstPort &&
            DstPort == other.SrcPort;

        return sameDirection || reverseDirection;
    }
};

struct FiveTupleHash
{
    std::size_t operator()(const FiveTuple& tuple) const
    {
        std::size_t seed        = 0;
        auto        hashCombine = [&seed]<typename T0>(T0 const& val)
        {
            seed ^= std::hash<std::decay_t<T0>>{}(val) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        };

        // Normalize so that (A->B) and (B->A) produce the same hash
        bool isDirectOrder =
            tuple.SrcIp < tuple.DstIp ||
            (tuple.SrcIp == tuple.DstIp && tuple.SrcPort <= tuple.DstPort);

        if (isDirectOrder)
        {
            hashCombine(tuple.SrcIp);
            hashCombine(tuple.DstIp);
            hashCombine(tuple.SrcPort);
            hashCombine(tuple.DstPort);
        }
        else
        {
            hashCombine(tuple.DstIp);
            hashCombine(tuple.SrcIp);
            hashCombine(tuple.DstPort);
            hashCombine(tuple.SrcPort);
        }

        hashCombine(tuple.TransProto);

        return seed;
    }
};

struct IpStatsInfo final : BaseDataObject
{
    virtual               ~IpStatsInfo() = default;
    std::string           Ip;
    std::string           Location;
    double                EarliestTime;
    double                LatestTime;
    std::set<int>         Ports;
    std::set<std::string> Protocols;

    int TotalSendPackets = 0;
    int TotalRecvPackets = 0;
    int TotalSendBytes   = 0;
    int TotalRecvBytes   = 0;
    int TcpSessionCount  = 0;
    int UdpSessionCount  = 0;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        obj.AddMember("ip", rapidjson::Value(Ip.c_str(), allocator), allocator);
        obj.AddMember("location", rapidjson::Value(Location.c_str(), allocator), allocator);

        std::string sProtocols = MiscUtil::ConvertSetToString(Protocols, ',');
        obj.AddMember("proto", rapidjson::Value(sProtocols.c_str(), allocator), allocator);

        rapidjson::Value portsValue;
        portsValue.SetArray();
        for (const auto& port : Ports)
        {
            portsValue.PushBack(rapidjson::Value(port), allocator);
        }
        obj.AddMember("ports", portsValue, allocator);
        obj.AddMember("earliest_time", EarliestTime, allocator);
        obj.AddMember("latest_time", LatestTime, allocator);
        obj.AddMember("total_send_packets", TotalSendPackets, allocator);
        obj.AddMember("total_recv_packets", TotalRecvPackets, allocator);
        obj.AddMember("total_send_bytes", TotalSendBytes, allocator);
        obj.AddMember("total_recv_bytes", TotalRecvBytes, allocator);
        obj.AddMember("tcp_session_count", TcpSessionCount, allocator);
        obj.AddMember("udp_session_count", UdpSessionCount, allocator);
    }
};

struct ProtoStatsInfo final : BaseDataObject
{
    virtual     ~ProtoStatsInfo() = default;
    std::string Protocol;
    int         TotalPackets = 0;
    int         TotalBytes   = 0;
    int         SessionCount = 0;
    std::string ProtoDesc;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        obj.AddMember("protocol", rapidjson::Value(Protocol.c_str(), allocator), allocator);
        obj.AddMember("total_packets", TotalPackets, allocator);
        obj.AddMember("total_bytes", TotalBytes, allocator);
        obj.AddMember("session_count", SessionCount, allocator);
        obj.AddMember("proto_desc", rapidjson::Value(ProtoDesc.c_str(), allocator), allocator);
    }
};

struct RegionStatsInfo final : BaseDataObject
{
    virtual     ~RegionStatsInfo() = default;
    std::string Region;
    int         IpCount      = 0;
    int         TotalPackets = 0;
    int         TotalBytes   = 0;
    int         SessionCount = 0;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        obj.AddMember("region", rapidjson::Value(Region.c_str(), allocator), allocator);
        obj.AddMember("ip_count", IpCount, allocator);
        obj.AddMember("total_packets", TotalPackets, allocator);
        obj.AddMember("total_bytes", TotalBytes, allocator);
        obj.AddMember("session_count", SessionCount, allocator);
    }
};

struct DataStreamItem final : BaseDataObject
{
    virtual     ~DataStreamItem() = default;
    std::string HexData;
    std::string SrcNode;
    std::string DstNode;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        obj.AddMember("hex_data", rapidjson::Value(HexData.c_str(), allocator), allocator);
        obj.AddMember("src_node", rapidjson::Value(SrcNode.c_str(), allocator), allocator);
        obj.AddMember("dst_node", rapidjson::Value(DstNode.c_str(), allocator), allocator);
    }
};

struct DataStreamCountInfo final : BaseDataObject
{
    uint32_t    TotalPacketCount = 0;
    std::string Node0;
    uint32_t    Node0PacketCount = 0;
    uint32_t    Node0BytesCount  = 0;
    std::string Node1;
    uint32_t    Node1PacketCount = 0;
    uint32_t    Node1BytesCount  = 0;

    void ToJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const override
    {
        obj.AddMember("total_packet_count", TotalPacketCount, allocator);
        obj.AddMember("node0", rapidjson::Value(Node0.c_str(), allocator), allocator);
        obj.AddMember("node0_packet_count", Node0PacketCount, allocator);
        obj.AddMember("node0_bytes_count", Node0BytesCount, allocator);
        obj.AddMember("node1", rapidjson::Value(Node1.c_str(), allocator), allocator);
        obj.AddMember("node1_packet_count", Node1PacketCount, allocator);
        obj.AddMember("node1_bytes_count", Node1BytesCount, allocator);
    }
};
