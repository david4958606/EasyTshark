#include "HttpUtil.h"

#include "BaseController.hpp"
#include "PageAndOrder.hpp"

httplib::Server::HandlerResponse HttpUtil::BeforeRequest(const httplib::Request& req, httplib::Response& res)
{
    std::cout << "\n";
    LOG_F(INFO, "[Before] URL: %s | IP: %s", req.path.c_str(), req.remote_addr.c_str());
    // page and order
    PageAndOrder* pageAndOrder = PageHelper::GetPageAndOrder();
    pageAndOrder->PageNum      = BaseController::GetIntParam(req, "pageNum", 1);
    pageAndOrder->PageSize     = BaseController::GetIntParam(req, "pageSize", 100);
    pageAndOrder->OrderBy      = BaseController::GetStringParam(req, "orderBy", "");
    pageAndOrder->DescOrAsc    = BaseController::GetStringParam(req, "descOrAsc", "asc");
    return httplib::Server::HandlerResponse::Unhandled;
}

void HttpUtil::AfterRequest(const httplib::Request& req, httplib::Response& res)
{
    if (req.method != "OPTIONS")
    {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:3000");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
    }
    LOG_F(INFO, "[After]  Status Code: %d", res.status);
    std::cout << "\n";
}
