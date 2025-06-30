#pragma once
#include "httplib.h"
#include "TsharkManager.h"
void InitIp2RegionUtil();
void InitLog(int argc, char* argv[]);
void GetDetailedJson(TsharkManager& tsharkManager);
void OnlineCapture(const std::shared_ptr<TsharkManager>& gPtrTsharkManager,
                   const std::string&                    adapterName,
                   int                                   duration = 0);
void OfflineAnalysis(const std::shared_ptr<TsharkManager>& gPtrTsharkManager);
void SetUpServer();
void BeforeRequest(const httplib::Request& req);
void AfterRequest(const httplib::Request& req, const httplib::Response& res);

inline std::shared_ptr<TsharkManager> gPtrTsharkManager;
