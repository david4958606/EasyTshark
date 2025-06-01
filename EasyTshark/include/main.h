#pragma once
#include "TsharkManager.h"
void InitIp2RegionUtil();
void InitLog(int argc, char* argv[]);
void GetDetailedJson(TsharkManager& tsharkManager);
void OnlineCapture(TsharkManager& tsharkManager, const std::string& adapterName);
void OfflineAnalysis(TsharkManager& tsharkManager);
