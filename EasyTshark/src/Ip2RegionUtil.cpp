#include "Ip2RegionUtil.h"

import <memory>;
import <string>;
import <iostream>;
import <sstream>;
import <vector>;


Ip2RegionUtil& Ip2RegionUtil::Instance()
{
    static Ip2RegionUtil instance;
    return instance;
}


/// @brief Init the xdb database
bool Ip2RegionUtil::Init(const std::string& xdbFilePath)
{
    if (!XdbPtr)
    {
        try
        {
            XdbPtr = std::make_shared<xdb_search_t>(xdbFilePath);
            XdbPtr->init_content();
        }
        catch (const std::exception& e)
        {
            std::cerr << "Failed to initialize xdb_search_t: " << e.what() << std::endl;
            return false;
        }
    }
    return true;
}

void Ip2RegionUtil::UnInit()
{
    return;
}


/// @brief Get the location of the IP address
std::string Ip2RegionUtil::GetIpLocation(const std::string& ip) const
{
    if (!XdbPtr)
    {
        std::cerr << "XdbPtr is not initialized." << std::endl;
        return "";
    }
    if (ip.size() > 15)
    {
        std::cerr << "Invalid IP address: " << ip << std::endl;
        return "";
    }

    const std::string location = XdbPtr->search(ip);
    if (!location.empty() && location.find("invalid") == std::string::npos)
    {
        return ParseLocation(location);
    }
    std::cerr << "Invalid IP address: " << ip << std::endl;
    return "";
}


/// @brief Parse the location string
std::string Ip2RegionUtil::ParseLocation(const std::string& input)
{
    if (input.find("内网") != std::string::npos)
    {
        return "内网";
    }

    std::vector<std::string> tokens;
    std::string              token;
    std::stringstream        ss(input);
    while (std::getline(ss, token, '|'))
    {
        tokens.push_back(token);
    }

    if (tokens.size() >= 4)
    {
        std::string result;
        if (tokens[0] != "0") result += tokens[0];
        if (tokens[2] != "0") result += "-" + tokens[2];
        if (tokens[3] != "0") result += "-" + tokens[3];
        return result;
    }
    return input;
}
