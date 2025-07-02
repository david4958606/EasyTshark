#pragma once
#include "httplib.h"

namespace HttpUtil
{
    httplib::Server::HandlerResponse BeforeRequest(const httplib::Request& req, httplib::Response& res);
    void                             AfterRequest(const httplib::Request& req, const httplib::Response& res);
}
