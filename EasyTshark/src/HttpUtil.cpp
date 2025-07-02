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

void HttpUtil::AfterRequest(const httplib::Request& req, const httplib::Response& res)
{
    LOG_F(INFO, "[After]  Status Code: %d", res.status);
    std::cout << "\n";
}
