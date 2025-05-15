#pragma once
import <string>;
import <memory>;

#include "xdb_search.h"

class Ip2RegionUtil
{
public:
    static Ip2RegionUtil& Instance();
    bool                  Init(const std::string& xdbFilePath);
    void                  UnInit();
    std::string           GetIpLocation(const std::string& ip) const;

private:
    Ip2RegionUtil()                                = default;
    ~Ip2RegionUtil()                               = default;
    Ip2RegionUtil(const Ip2RegionUtil&)            = delete;
    Ip2RegionUtil& operator=(const Ip2RegionUtil&) = delete;

    static std::string ParseLocation(const std::string& input);

    std::shared_ptr<xdb_search_t> XdbPtr = nullptr;
};
