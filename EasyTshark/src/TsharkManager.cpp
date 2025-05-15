#include "TsharkManager.h"

import <iostream>;
import <format>;
import <cassert>;
import <sstream>;
import <fstream>;
import <chrono>;


#include "document.h"
#include "writer.h"
#include "stringbuffer.h"
#include "Ip2RegionUtil.h"
#include "loguru.hpp"
#include "TsharkDataType.h"


TsharkManager::TsharkManager(const std::string& workDir)
{
    this->TsharkPath          = "\"C:\\Program Files\\Wireshark\\tshark.exe\"";
    const std::string xdbPath = workDir + "resource\\ip2region.xdb";
    IpUtil.Init(xdbPath);
}

TsharkManager::~TsharkManager()
{
    IpUtil.UnInit();
}

bool TsharkManager::ReadPcap(const std::string& path)
{
    const std::vector<std::string> tsharkArgs = {
        TsharkPath,
        "-r", path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };

    std::string command;

    for (const auto arg : tsharkArgs)
    {
        command += arg;
        command += " ";
    }

    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Failed to open pipe." << std::endl;
        return false;
    }

    char buffer[4096];

    uint32_t fileOffset = sizeof(PcapHeader); // point to the first packet
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        const auto packet = std::make_shared<Packet>();
        if (!ParseLine(buffer, packet))
        {
            LOG_F(ERROR, buffer);
            assert(false);
        }
        packet->FileOffset = fileOffset + sizeof(PacketHeader);
        fileOffset += sizeof(PacketHeader) + packet->CapLen;

        packet->SourceLocation      = IpUtil.GetIpLocation(packet->SourceIp);
        packet->DestinationLocation = IpUtil.GetIpLocation(packet->DestinationIp);

        AllPackets.insert(std::make_pair<>(packet->FrameNumber, packet));
    }


    if (_pclose(pipe) == -1)
    {
        std::cerr << "Failed to close pipe." << std::endl;
    }
    CurrentFilePath = path;
    return true;
}

void TsharkManager::PrintAllPackets() const
{
    for (const auto& [fst, snd] : AllPackets)
    {
        const std::shared_ptr<Packet> packet = snd;

        rapidjson::Document pktObj;
        AllocatorType       allocator = pktObj.GetAllocator();
        pktObj.SetObject();

        pktObj.AddMember("frame_number", packet->FrameNumber, allocator);
        pktObj.AddMember("timestamp", rapidjson::Value(packet->Time.c_str(), allocator), allocator);
        pktObj.AddMember("src_mac", rapidjson::Value(packet->SourceMac.c_str(), allocator), allocator);
        pktObj.AddMember("dst_mac", rapidjson::Value(packet->DestinationMac.c_str(), allocator), allocator);
        pktObj.AddMember("src_ip", rapidjson::Value(packet->SourceIp.c_str(), allocator), allocator);
        pktObj.AddMember("src_location", rapidjson::Value(packet->SourceLocation.c_str(), allocator), allocator);
        pktObj.AddMember("src_port", packet->SourcePort, allocator);
        pktObj.AddMember("dst_ip", rapidjson::Value(packet->DestinationIp.c_str(), allocator), allocator);
        pktObj.AddMember("dst_location", rapidjson::Value(packet->DestinationLocation.c_str(), allocator), allocator);
        pktObj.AddMember("dst_port", packet->DestinationPort, allocator);
        pktObj.AddMember("protocol", rapidjson::Value(packet->Protocol.c_str(), allocator), allocator);
        pktObj.AddMember("info", rapidjson::Value(packet->Info.c_str(), allocator), allocator);
        pktObj.AddMember("file_offset", packet->FileOffset, allocator);
        pktObj.AddMember("cap_len", packet->CapLen, allocator);
        pktObj.AddMember("len", packet->Len, allocator);

        rapidjson::StringBuffer                    buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pktObj.Accept(writer);

        std::cout << buffer.GetString() << std::endl;
    }
}

bool TsharkManager::ReadPacketHex(const uint32_t              frameNumber,
                                  std::vector<unsigned char>& data)
{
    const auto it = AllPackets.find(frameNumber);
    if (it == AllPackets.end())
    {
        return false;
    }
    const std::shared_ptr<Packet>& packet = it->second;

    std::ifstream file(CurrentFilePath, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << CurrentFilePath << std::endl;
        return false;
    }

    const uint32_t offset = packet->FileOffset;
    const uint32_t length = packet->CapLen;
    // Seek to the specified offset
    file.seekg(offset, std::ios::beg);
    if (!file)
    {
        std::cerr << "Failed to seek to offset: " << offset << std::endl;
        return false;
    }
    // Read the specified length of data
    data.resize(length);
    file.read(reinterpret_cast<char*>(data.data()), length);
    if (!file)
    {
        std::cerr << "Failed to read data from file." << std::endl;
        return false;
    }
    // Check if the read was successful
    if (file.gcount() != length)
    {
        std::cerr << "Read less data than expected." << std::endl;
        return false;
    }
    file.close();
    return true;
}

bool TsharkManager::ParseLine(std::string line, const std::shared_ptr<Packet>& packet)
{
    if (line.back() == '\n')
    {
        line.pop_back();
    }

    std::stringstream        ss(line);
    std::string              field;
    std::vector<std::string> fields;

    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos)
    {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start));

    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info
    if (fields.size() >= 16)
    {
        packet->FrameNumber    = std::stoi(fields[0]);
        packet->Time           = ConvertTimeStamp(fields[1]);
        packet->Len            = std::stoi(fields[2]);
        packet->CapLen         = std::stoi(fields[3]);
        packet->SourceMac      = fields[4];
        packet->DestinationMac = fields[5];
        packet->SourceIp       = fields[6].empty() ? fields[7] : fields[6];
        packet->DestinationIp  = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty())
        {
            packet->SourcePort = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }
        if (!fields[12].empty() || !fields[13].empty())
        {
            packet->DestinationPort = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->Protocol = fields[14];
        packet->Info     = fields[15];

        return true;
    }
    return false;
}

std::string TsharkManager::ConvertTimeStamp(const std::string& timestampStr)
{
    const size_t dotPos = timestampStr.find('.');
    if (dotPos == std::string::npos)
    {
        LOG_F(ERROR, "Invalid timestamp format.");
        throw std::invalid_argument("Invalid timestamp format.");
    }

    const std::string secPartStr  = timestampStr.substr(0, dotPos);
    std::string       fracPartStr = timestampStr.substr(dotPos + 1);

    while (fracPartStr.length() < 6) fracPartStr += '0';
    if (fracPartStr.length() > 6) fracPartStr = fracPartStr.substr(0, 6);
    const std::time_t seconds = std::stoll(secPartStr);
    const int         micros  = std::stoi(fracPartStr);

    // 转为系统时间
    std::tm tm = *std::gmtime(&seconds); // 若想用本地时间可换成 std::localtime

    // 格式化输出
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    oss << "." << std::setw(6) << std::setfill('0') << micros;

    return oss.str();
}
