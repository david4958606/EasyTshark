#include "TsharkManager.h"

#include <iostream>
#include <format>
#include <cassert>
#include <sstream>
#include <fstream>
#include <chrono>
#include <set>
#include <regex>
#include <thread>
#include <ranges>
#include <ctime>

#include "document.h"
#include "writer.h"
#include "stringbuffer.h"
#include "Ip2RegionUtil.h"
#include "loguru.hpp"
#include "TsharkDataType.h"


TsharkManager::TsharkManager(const std::string& workDir): StopFlag(false)
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

    FILE* pipe = POPEN(command.c_str(), "r");
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


    if (PCLOSE(pipe) == -1)
    {
        std::cerr << "Failed to close pipe." << std::endl;
    }
    CurrentFilePath = path;
    return true;
}

void TsharkManager::PrintAllPackets() const
{
    for (const auto& snd : AllPackets | std::views::values)
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

        // std::cout << buffer.GetString() << std::endl;
        LOG_F(INFO, buffer.GetString());
    }
    LOG_F(INFO, "Analyse Complete! Total packets: %d", AllPackets.size());
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
        const std::string err = "Failed to open file: " + CurrentFilePath;
        LOG_F(ERROR, err.c_str());
        return false;
    }

    const uint32_t offset = packet->FileOffset;
    const uint32_t length = packet->CapLen;
    // Seek to the specified offset
    file.seekg(offset, std::ios::beg);
    if (!file)
    {
        const std::string err = "Failed to seek to offset: " + std::to_string(offset);
        LOG_F(ERROR, err.c_str());
        return false;
    }
    // Read the specified length of data
    data.resize(length);
    file.read(reinterpret_cast<char*>(data.data()), length);
    if (!file)
    {
        LOG_F(ERROR, "Failed to read data from file.");
        return false;
    }
    // Check if the read was successful
    if (file.gcount() != length)
    {
        LOG_F(ERROR, "Read less data than expected.");
        return false;
    }
    file.close();
    return true;
}

std::vector<AdapterInfo> TsharkManager::GetNetworkAdapters() const
{
    std::set<std::string> specialInterfaces = { "sshdump", "ciscodump", "udpdump", "randpkt", "USBPcap1", "etwdump" };
    std::vector<AdapterInfo> interfaces;

    std::string                              cmd = TsharkPath + " -D";
    std::unique_ptr<FILE, decltype(&PCLOSE)> pipe(POPEN(cmd.c_str(), "r"), PCLOSE);
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to open pipe.");
        throw std::runtime_error("Failed to run tshark command.");
    }

    std::ostringstream output;
    char               buffer[512];
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr)
    {
        output << buffer;
    }

    std::regex         lineRegex(R"(^\d+\.\s+([^\s]+)\s+\((.+)\)$)");
    std::regex         simpleRegex(R"(^\d+\.\s+([^\s]+)$)");
    std::istringstream stream(output.str());
    std::string        line;
    int                index = 1;

    while (std::getline(stream, line))
    {
        std::smatch match;
        AdapterInfo adapter;

        if (std::regex_match(line, match, lineRegex) && match.size() == 3)
        {
            adapter.Name   = match[1];
            adapter.Remark = match[2];
        }
        else if (std::regex_match(line, match, simpleRegex) && match.size() == 2)
        {
            adapter.Name = match[1];
        }
        else
        {
            continue; // Unrecognized line format
        }

        if (specialInterfaces.contains(adapter.Name)) continue;

        adapter.Id = index++;
        interfaces.push_back(adapter);
    }
    return interfaces;
}

bool TsharkManager::StartCapture(const std::string& adapterName)
{
    LOG_F(INFO, "Starting Capture @ %s", adapterName.c_str());
    StopFlag          = false;
    CaptureWorkThread = std::make_shared<std::thread>(&TsharkManager::CaptureWorkThreadEntry, this,
                                                      "\"" + adapterName + "\"");
    return true;
}

bool TsharkManager::StopCapture()
{
    LOG_F(INFO, "Stopping Capture...");
    StopFlag = true;
    ProcessUtil::Kill(CaptureTsharkPid);
    CaptureWorkThread->join();
    return true;
}

void TsharkManager::StartMonitorAdaptersFlowTrend()
{
    std::unique_lock<std::recursive_mutex> lock(AdapterFlowTrendMapLock);

    AdapterFlowTrendMonitorStartTime = time(nullptr);

    for (std::vector<AdapterInfo> adapterList = GetNetworkAdapters(); auto& adapter : adapterList)
    {
        AdapterFlowTrendMonitorMap.insert(std::make_pair<>(adapter.Name, AdapterMonitorInfo()));
        AdapterMonitorInfo& monitorInfo = AdapterFlowTrendMonitorMap.at(adapter.Name);

        monitorInfo.MonitorThread = std::make_shared<std::thread>(&TsharkManager::AdapterFlowTrendMonitorThreadEntry,
                                                                  this, adapter.Name);
        if (monitorInfo.MonitorThread == nullptr)
        {
            LOG_F(ERROR, "Failed to create monitor process on %s", adapter.Name.c_str());
        }
        else
        {
            LOG_F(INFO, "Success to create monitor process on：%s，monitorThread: %p",
                  adapter.Name.c_str(),
                  monitorInfo.MonitorThread.get());
        }
    }
}

void TsharkManager::StopMonitorAdaptersFlowTrend()
{
    std::unique_lock<std::recursive_mutex> lock(AdapterFlowTrendMapLock);
    for (const auto& val : AdapterFlowTrendMonitorMap | std::views::values)
    {
        ProcessUtil::Kill(val.TsharkPid);
    }

    for (auto& [fst, snd] : AdapterFlowTrendMonitorMap)
    {
        // 然后关闭管道
        PCLOSE(snd.MonitorTsharkPipe);

        // 最后等待对应线程退出
        snd.MonitorThread->join();

        LOG_F(INFO, "Stop monitor flow on %s", fst.c_str());
    }
    AdapterFlowTrendMonitorMap.clear();
}

void TsharkManager::GetAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData)
{
    const auto timeNow = time(nullptr);

    // 数据从最左边冒出来
    // 一开始：以最开始监控时间为左起点，终点为未来300秒
    // 随着时间推移，数据逐渐填充完这300秒
    // 超过300秒之后，结束节点就是当前，开始节点就是当前-300
    const auto startWindow = timeNow - AdapterFlowTrendMonitorStartTime > 300
                                 ? timeNow - 300
                                 : AdapterFlowTrendMonitorStartTime;
    const auto endWindow = timeNow - AdapterFlowTrendMonitorStartTime > 300
                               ? timeNow
                               : AdapterFlowTrendMonitorStartTime + 300;

    AdapterFlowTrendMapLock.lock();
    for (auto [fst, snd] : AdapterFlowTrendMonitorMap)
    {
        flowTrendData.insert(std::make_pair<>(fst, std::map<long, long>()));

        // 从当前时间戳向前倒推300秒，构造map
        for (time_t t = startWindow; t <= endWindow; t++)
        {
            // 如果trafficPerSecond中存在该时间戳，则使用已有数据；否则填充为0
            if (snd.FlowTrendData.contains(t))
            {
                flowTrendData[fst][t] = snd.FlowTrendData.at(t);
            }
            else
            {
                flowTrendData[fst][t] = 0;
            }
        }
    }

    AdapterFlowTrendMapLock.unlock();
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

using namespace std::chrono;

std::string TsharkManager::ConvertTimeStamp(const std::string& timestampStr)
{
    const size_t dotPos = timestampStr.find('.');
    if (dotPos == std::string::npos)
    {
        throw std::invalid_argument("Invalid timestamp format.");
    }

    // 拆分整数秒与微秒部分
    const std::string secPartStr  = timestampStr.substr(0, dotPos);
    std::string       fracPartStr = timestampStr.substr(dotPos + 1);

    // 补齐/截断到6位微秒
    if (fracPartStr.size() > 6) fracPartStr = fracPartStr.substr(0, 6);
    while (fracPartStr.size() < 6) fracPartStr += '0';

    const seconds      secs   = seconds{ std::stoll(secPartStr) };
    const microseconds micros = microseconds{ std::stoi(fracPartStr) };

    // 构造 UTC 时间点
    const sys_time<microseconds> tp = time_point_cast<microseconds>(sys_seconds{ secs } + micros);

    // 使用 std::format 输出（UTC时间）："2025-05-19 08:52:34.123456"
    return std::format("{:%Y-%m-%d %H:%M:%S}.{:06}", tp, micros.count() % 1'000'000);
}

void TsharkManager::CaptureWorkThreadEntry(const std::string& adapterName)
{
    std::string              captureFile = "resource\\capture.pcap";
    std::vector<std::string> tsharkArgs  = {
        TsharkPath,
        "-i", adapterName.c_str(),
        "-w", captureFile, // 默认将采集到的数据包写入到这个文件下
        "-F", "pcap",      // 指定存储的格式为PCAP格式
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
    // command += "\"";
    for (const auto arg : tsharkArgs)
    {
        command += arg;
        command += " ";
    }
    // command += "\"";
    // std::cout << command << std::endl;
    FILE* pipe = ProcessUtil::PopenEx(command.c_str(), &CaptureTsharkPid);
    if (!pipe)
    {
        LOG_F(ERROR, "Failed to run tshark command!");
        return;
    }

    char buffer[4096];

    uint32_t fileOffset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr && !StopFlag)
    {
        std::string line = buffer;
        if (line.find("Capturing on") != std::string::npos)
        {
            continue;
        }

        auto packet = std::make_shared<Packet>();
        if (!ParseLine(buffer, packet))
        {
            LOG_F(ERROR, buffer);
            assert(false);
        }
        packet->FileOffset = fileOffset + sizeof(PacketHeader);

        fileOffset += sizeof(PacketHeader) + packet->CapLen;
        packet->SourceLocation = IpUtil.GetIpLocation(packet->SourceIp);
        packet->DestinationIp  = IpUtil.GetIpLocation(packet->DestinationIp);

        AllPackets.insert(std::make_pair<>(packet->FrameNumber, packet));
    }
}

void TsharkManager::AdapterFlowTrendMonitorThreadEntry(std::string adapterName)
{
    AdapterFlowTrendMapLock.lock();
    if (!AdapterFlowTrendMonitorMap.contains(adapterName))
    {
        AdapterFlowTrendMapLock.unlock();
        return;
    }
    AdapterFlowTrendMapLock.unlock();
    char buffer[256] = { 0 };
    std::map<long, long>& trafficPerSecond = AdapterFlowTrendMonitorMap[adapterName].FlowTrendData;
    const std::string tsharkCmd = TsharkPath + " -i \"" + adapterName + "\" -T fields -e frame.time_epoch -e frame.len";

    LOG_F(INFO, "Start flow monitor on: %s", tsharkCmd.c_str());

    PidT  tsharkPid = 0;
    FILE* pipe      = ProcessUtil::PopenEx(tsharkCmd.c_str(), &tsharkPid);
    if (!pipe)
    {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // Save the pipe
    AdapterFlowTrendMapLock.lock();
    AdapterFlowTrendMonitorMap[adapterName].MonitorTsharkPipe = pipe;
    AdapterFlowTrendMonitorMap[adapterName].TsharkPid         = tsharkPid;
    AdapterFlowTrendMapLock.unlock();

    // Read the output from tshark
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        std::string        line(buffer);
        std::istringstream iss(line);
        std::string        timestampStr, lengthStr;

        if (line.find("Capturing") != std::string::npos || line.find("captured") != std::string::npos)
        {
            continue;
        }

        // Parse the timestamp and length from the line
        if (!(iss >> timestampStr >> lengthStr))
        {}
        try
        {
            long       timestamp    = static_cast<long>(std::stod(timestampStr));
            const long packetLength = std::stol(lengthStr);
            trafficPerSecond[timestamp] += packetLength;
            while (trafficPerSecond.size() > 300)
            {
                LOG_F(INFO, "Removing old data for second: %ld, Traffic: %ld bytes",
                      trafficPerSecond.begin()->first,
                      trafficPerSecond.begin()->second);
                trafficPerSecond.erase(trafficPerSecond.begin());
            }
        }
        catch (const std::exception& e)
        {
            LOG_F(ERROR, "Error parsing tshark output: %s", line.c_str());
            LOG_F(ERROR, "Exception: %s", e.what());
        }
    }
    LOG_F(INFO, "adapterFlowTrendMonitorThreadEntry ENDED");
}
