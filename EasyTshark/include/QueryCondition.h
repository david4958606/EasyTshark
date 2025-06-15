#pragma once
#include <string>

class QueryCondition
{
public:
    std::string Ip;
    uint16_t    Port = 0;
    std::string Proto;
    std::string Mac;
    std::string Location;
};
