#pragma once
#include <string>
#include <fstream>
#include <sstream>

#include "rapidxml.hpp"
#include "document.h"
#include "writer.h"
#include "prettywriter.h"
#include "stringbuffer.h"

#include "document.h"

namespace MiscUtil
{
    std::string GetRandomString(const size_t length);
    bool        Xml2Json(std::string xmlContent, rapidjson::Document& outJsonDoc);
    void        XmlToJsonRecursive(rapidjson::Value&            json,
                            rapidxml::xml_node<>*               node,
                            rapidjson::Document::AllocatorType& allocator);
}
