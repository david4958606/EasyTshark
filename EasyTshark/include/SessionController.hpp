#pragma once
#include "BaseController.hpp"

class SessionController : public BaseController
{
public:
    SessionController(httplib::Server& server, const std::shared_ptr<TsharkManager>& tsharkManager)
        : BaseController(server, tsharkManager)
    {}

    void GetSessionList(const httplib::Request& req, httplib::Response& res)
    {
        try
        {
            QueryCondition queryCondition;
            if (!ParseQueryCondition(req, queryCondition))
            {
                SendErrorResponse(res, ERROR_PARAMETER_WRONG);
                return;
            }
            std::vector<std::shared_ptr<Session>> sessionList;
            __TsharkManager->QuerySessions(queryCondition, sessionList);
            int total = sessionList.size();
            SendDataList(res, sessionList, total);
        }
        catch (const std::exception&)
        {
            SendErrorResponse(res, ERROR_INTERNAL_WRONG);
        }
    }

    void RegisterRoute() override
    {
        __Server.Post("/api/getSessionList", [this](const httplib::Request& req, httplib::Response& res)
        {
            GetSessionList(req, res);
        });
    }
};
