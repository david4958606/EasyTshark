#include "httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "loguru.hpp"

#include <string>

using namespace httplib;
using namespace rapidjson;

const std::string K_AUTH_TOKEN = "Bearer 12345678";

void BeforeRequest(const Request& req)
{
    LOG_F(INFO, "[Before] URL: %s | IP: %s", req.path.c_str(), req.remote_addr.c_str());
}

void AfterRequest(const Request& req, const Response& res)
{
    LOG_F(INFO, "[After]  Status Code: %d", res.status);
}

int main(int argc, char* argv[])
{
    loguru::init(argc, argv);
    loguru::add_file("server.log", loguru::Append, loguru::Verbosity_MAX);
    LOG_F(INFO, "Starting server...");

    Server svr;

    svr.set_pre_routing_handler([](const Request& req, Response& /*res*/)
    {
        BeforeRequest(req);
        return Server::HandlerResponse::Unhandled;
    });

    svr.set_post_routing_handler([](const Request& req, const Response& res)
    {
        AfterRequest(req, res);
    });

    svr.Get("/user_info", [](const Request& req, Response& res)
    {
        if (auto authIt = req.headers.find("Authorization"); authIt == req.headers.end() || authIt->second !=
            K_AUTH_TOKEN)
        {
            res.status = 401;
            res.set_content("Unauthorized", "text/plain");
            LOG_F(WARNING, "Unauthorized access attempt from IP: %s", req.remote_addr.c_str());
            return;
        }

        std::string username, ageStr;
        if (req.has_param("username"))
        {
            username = req.get_param_value("username");
        }
        if (req.has_param("age"))
        {
            ageStr = req.get_param_value("age");
        }

        if (username.empty() || ageStr.empty())
        {
            res.status = 400;
            res.set_content("Missing username or age", "text/plain");
            LOG_F(ERROR, "Bad request: missing parameters");
            return;
        }

        int      age = std::stoi(ageStr);
        Document doc;
        doc.SetObject();
        Document::AllocatorType& alloc = doc.GetAllocator();

        doc.AddMember("status", "success", alloc);
        doc.AddMember("username", StringRef(username.c_str()), alloc);
        doc.AddMember("age", age, alloc);

        std::string message = "Hello, " + username + "! You are " + std::to_string(age) + " years old.";
        doc.AddMember("message", StringRef(message.c_str()), alloc);

        StringBuffer         buffer;
        Writer<StringBuffer> writer(buffer);
        doc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
        LOG_F(INFO, "Served user_info for '%s'", username.c_str());
    });

    LOG_F(INFO, "Server running at http://0.0.0.0:8080");
    svr.listen("0.0.0.0", 8080);
}
