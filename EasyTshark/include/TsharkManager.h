#pragma once
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>


#include "AdapterMonitorInfo.h"
#include "document.h"
#include "Ip2RegionUtil.h"
#include "TsharkDataType.h"
#include "ProcessUtil.h"
#include "TsharkDatabase.hpp"
#include "QueryCondition.h"

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#endif

enum WorkStatus
{
    STATUS_IDLE          = 0,
    STATUS_ANALYSIS_FILE = 1,
    STATUS_CAPTURING     = 2,
    STATUS_MONITORING    = 3
};

class TsharkManager
{
public:
    explicit TsharkManager(const std::string& workDir);
    ~TsharkManager();

    // analyze pcap file
    bool AnalysisFile(const std::string& path);
    void PrintAllPackets() const;
    bool ReadPacketHex(uint32_t frameNumber, std::vector<unsigned char>& data);

    std::vector<AdapterInfo> GetNetworkAdapters() const;

    bool StartCapture(const std::string& adapterName);
    bool StopCapture();

    void StartMonitorAdaptersFlowTrend();
    void StopMonitorAdaptersFlowTrend();
    void GetAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    bool GetPackageDetailInfo(uint32_t frameNumber, std::string& result) const;

    // Database
    void QueryPackets(const QueryCondition&                 queryCondition,
                      std::vector<std::shared_ptr<Packet>>& packets,
                      int&                                  total) const;
    void QuerySessions(const QueryCondition&                  condition,
                       std::vector<std::shared_ptr<Session>>& sessionList,
                       int&                                   total);
    void QueryIpStats(const QueryCondition&                      condition,
                      std::vector<std::shared_ptr<IpStatsInfo>>& ipStatsList,
                      int&                                       total) const;

    void QueryProtocolStats(const QueryCondition&                         condition,
                            std::vector<std::shared_ptr<ProtoStatsInfo>>& protoStatsList,
                            int&                                          total) const;

    void QueryRegionStats(const QueryCondition&                          condition,
                          std::vector<std::shared_ptr<RegionStatsInfo>>& regionStatsList,
                          int&                                           total) const;

    bool ConvertToPcap(const std::string& inputFile, const std::string& outputFile) const;

    WorkStatus GetWorkStatus();
    void       Reset();

    void                PrintAllSessions() const;
    DataStreamCountInfo GetSessionDataStream(uint32_t                     sessionId,
                                             std::vector<DataStreamItem>& dataStreamList);

private:
    static bool ParseLine(std::string line, const std::shared_ptr<Packet>& packet);

    static std::string ConvertTimeStamp(double timestamp);

    std::string TsharkPath;
    std::string CurrentFilePath;
    std::string EditcapPath;
    std::string WorkDir;

    Ip2RegionUtil& IpUtil = Ip2RegionUtil::Instance();

    std::unordered_map<uint32_t, std::shared_ptr<Packet>> AllPackets;

    void CaptureWorkThreadEntry(const std::string& adapterName);

    std::shared_ptr<std::thread> CaptureWorkThread;

    bool StopFlag;

    PidT CaptureTsharkPid = 0;

    std::map<std::string, AdapterMonitorInfo> AdapterFlowTrendMonitorMap;
    std::recursive_mutex                      AdapterFlowTrendMapLock;
    time_t                                    AdapterFlowTrendMonitorStartTime = 0;

    void AdapterFlowTrendMonitorThreadEntry(const std::string& adapterName);

    std::vector<std::shared_ptr<Packet>> PacketsToBeStore;
    std::mutex                           StoreLock;
    std::shared_ptr<std::thread>         StorageThread;
    std::shared_ptr<TsharkDatabase>      Storage;
    void                                 StorageThreadEntry();
    void                                 ProcessPacket(std::shared_ptr<Packet> packet);

    WorkStatus           WorkStatus = STATUS_IDLE;
    std::recursive_mutex WorkStatusLock;

    std::unordered_map<FiveTuple, std::shared_ptr<Session>, FiveTupleHash> SessionMap;

    inline static const std::map<uint8_t, std::string> IP_PROTO_MAP = {
        { 1, "ICMP" },
        { 2, "IGMP" },
        { 6, "TCP" },
        { 17, "UDP" },
        { 47, "GRE" },
        { 50, "ESP" },
        { 51, "AH" },
        { 88, "EIGRP" },
        { 89, "OSPF" },
        { 132, "SCTP" }
    };

    std::unordered_set<std::shared_ptr<Session>> SessionSetTobeStore;

    std::map<uint32_t, std::shared_ptr<Session>> SessionIdMap;
};

typedef rapidjson::Document::AllocatorType& AllocatorType;
