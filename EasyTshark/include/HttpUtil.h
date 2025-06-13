#pragma once
#include "httplib.h"

namespace HttpUtil
{
    void QueryPacket(const httplib::Request& req, httplib::Response& res);
}
