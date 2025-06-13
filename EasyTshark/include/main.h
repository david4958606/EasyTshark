#pragma once
#include "httplib.h"
#include "TsharkManager.h"
void InitIp2RegionUtil();
void InitLog(int argc, char* argv[]);
void GetDetailedJson(TsharkManager& tsharkManager);
void OnlineCapture(TsharkManager& tsharkManager, const std::string& adapterName);
void OfflineAnalysis(TsharkManager& tsharkManager);
void SetUpServer();
void BeforeRequest(const httplib::Request& req);
void AfterRequest(const httplib::Request& req, const httplib::Response& res);

inline std::shared_ptr<TsharkManager> gPtrTsharkManager;
