import <sstream>;
import <vector>;
import <iostream>;
import <fstream>;
import <string>;
import <format>;

#include "Packet.h"
#include "document.h"
#include "Ip2RegionUtil.h"
#include "writer.h"
#include "stringbuffer.h"

void ParseLine(std::string line, Packet& packet)
{
    if (line.back() == '\n')
    {
        line.pop_back();
    }
    std::stringstream        ss(line);
    std::string              field;
    std::vector<std::string> fields;

    // 字符串拆分
    size_t start = 0, end;
    while ((end = line.find('\t', start)) != std::string::npos)
    {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    fields.push_back(line.substr(start)); // 添加最后一个子串

    if (fields.size() >= 13)
    {
        packet.FrameNumber = std::stoi(fields[0]);
        packet.Time        = fields[1];
        packet.CapLen      = std::stoi(fields[2]);
        packet.SourceIp    = fields[3].empty() ? fields[4] : fields[3];

        if (!fields[5].empty() || !fields[6].empty())
        {
            packet.SourcePort = std::stoi(fields[5].empty() ? fields[6] : fields[5]);
        }

        packet.DestinationIp = fields[7].empty() ? fields[8] : fields[7];

        if (!fields[9].empty() || !fields[10].empty())
        {
            packet.DestinationPort = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
        }

        packet.Protocol = fields[11];
        packet.Info     = fields[12];
    }
}


void PrintPacket(const Packet& packet)
{
    rapidjson::Document pktObj;
    AllocatorType       allocator           = pktObj.GetAllocator();
    const std::string   sourceLocation      = LookUpIp(packet.SourceIp);
    const std::string   destinationLocation = LookUpIp(packet.DestinationIp);
    pktObj.SetObject();
    pktObj.AddMember("FrameNumber", packet.FrameNumber, allocator);
    pktObj.AddMember("Time", rapidjson::Value(packet.Time.c_str(), allocator), allocator);
    pktObj.AddMember("CapLen", packet.CapLen, allocator);
    pktObj.AddMember("SourceIp", rapidjson::Value(packet.SourceIp.c_str(), allocator), allocator);
    pktObj.AddMember("SourceLocation", rapidjson::Value(sourceLocation.c_str(), allocator), allocator);
    pktObj.AddMember("SourcePort", packet.SourcePort, allocator);
    pktObj.AddMember("DestinationIp", rapidjson::Value(packet.DestinationIp.c_str(), allocator), allocator);
    pktObj.AddMember("DestinationLocation", rapidjson::Value(destinationLocation.c_str(), allocator), allocator);
    pktObj.AddMember("DestinationPort", packet.DestinationPort, allocator);
    pktObj.AddMember("Protocol", rapidjson::Value(packet.Protocol.c_str(), allocator), allocator);
    pktObj.AddMember("Info", rapidjson::Value(packet.Info.c_str(), allocator), allocator);
    pktObj.AddMember("FileOffset", packet.FileOffset, allocator);

    rapidjson::StringBuffer                    buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    pktObj.Accept(writer);

    std::cout << buffer.GetString() << std::endl;
}


void ReadPcap(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << path << std::endl;
        return;
    }

    // Read PCAP global header
    PcapHeader pcapHeader;
    file.read(reinterpret_cast<char*>(&pcapHeader), sizeof(PcapHeader));

    while (file)
    {
        // Read packet header
        PacketHeader packetHeader;
        file.read(reinterpret_cast<char*>(&packetHeader), sizeof(PacketHeader));
        if (!file)
            break;
        // Read packet data
        std::vector<char> packetData(packetHeader.CapLen);
        file.read(packetData.data(), packetHeader.CapLen);
        // Process the packet data (for demonstration, we just print the size)
        std::cout << std::format("Packet[Time: {}\tLen: {}]: ",
                                 packetHeader.TsSec,
                                 packetHeader.CapLen);
        for (unsigned char byte : packetData)
        {
            std::cout << std::format("{:02x} ", byte);
        }
        std::cout << std::endl;
    }
    file.close();
    std::cout << "Finished reading PCAP file." << std::endl;
}


bool ReadPacketHex(const std::string&          filePath,
                   const uint32_t              offset,
                   const uint32_t              length,
                   std::vector<unsigned char>& buffer)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }
    // Seek to the specified offset
    file.seekg(offset, std::ios::beg);
    if (!file)
    {
        std::cerr << "Failed to seek to offset: " << offset << std::endl;
        return false;
    }
    // Read the specified length of data
    buffer.resize(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
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


std::string LookUpIp(const std::string& ip)
{
    return Ip2RegionUtil::Instance().GetIpLocation(ip);
}
