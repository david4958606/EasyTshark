#include "MiscUtil.h"

#include <iostream>
#include <random>

std::string MiscUtil::GetRandomString(const size_t length)
{
    const std::string chars = "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    std::random_device              rd;
    std::mt19937                    generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string randomString;
    for (size_t i = 0; i < length; ++i)
    {
        randomString += chars[distribution(generator)];
    }

    return randomString;
}

bool MiscUtil::Xml2Json(std::string xmlContent, rapidjson::Document& outJsonDoc)
{
    // 解析 XML
    rapidxml::xml_document<> doc;
    try
    {
        doc.parse<0>(&xmlContent[0]);
    }
    catch (const rapidxml::parse_error& e)
    {
        std::cout << "XML Parsing error: " << e.what() << std::endl;
        return false;
    }

    // 创建 JSON 文档
    outJsonDoc.SetObject();
    rapidjson::Document::AllocatorType& allocator = outJsonDoc.GetAllocator();

    // 获取 XML 根节点
    rapidxml::xml_node<>* root = doc.first_node();
    if (root)
    {
        // 将根节点转换为 JSON
        rapidjson::Value root_json(rapidjson::kObjectType);
        XmlToJsonRecursive(root_json, root, allocator);

        // 将根节点添加到 JSON 文档
        outJsonDoc.AddMember(rapidjson::Value(root->name(), allocator).Move(), root_json, allocator);
    }
    return true;
}

void MiscUtil::XmlToJsonRecursive(rapidjson::Value&                   json,
                                  rapidxml::xml_node<>*               node,
                                  rapidjson::Document::AllocatorType& allocator)
{
    for (rapidxml::xml_node<>* curNode = node->first_node(); curNode; curNode = curNode->next_sibling())
    {
        // 检查是否需要跳过节点
        if (rapidxml::xml_attribute<>* hideAttr = curNode->first_attribute("hide"); hideAttr && std::string(
            hideAttr->value()) == "yes")
        {
            continue; // 如果 hide 属性值为 "true"，跳过该节点
        }

        // 检查是否已经有该节点名称的数组
        rapidjson::Value* array = nullptr;
        if (json.HasMember(curNode->name()))
        {
            array = &json[curNode->name()];
        }
        else
        {
            rapidjson::Value nodeArray(rapidjson::kArrayType); // 创建新的数组
            json.AddMember(rapidjson::Value(curNode->name(), allocator).Move(), nodeArray, allocator);
            array = &json[curNode->name()];
        }

        // 创建一个 JSON 对象代表当前节点
        rapidjson::Value childJson(rapidjson::kObjectType);

        // 处理节点的属性
        for (rapidxml::xml_attribute<>* attr = curNode->first_attribute(); attr; attr = attr->next_attribute())
        {
            rapidjson::Value attr_name(attr->name(), allocator);
            rapidjson::Value attr_value(attr->value(), allocator);
            childJson.AddMember(attr_name, attr_value, allocator);
        }

        // 递归处理子节点
        XmlToJsonRecursive(childJson, curNode, allocator);

        // 将当前节点对象添加到对应数组中
        array->PushBack(childJson, allocator);
    }
}

void MiscUtil::TranslateShowNameFields(rapidjson::Value& value, rapidjson::Document::AllocatorType& allocator)
{
    if (value.IsObject())
    {
        if (value.HasMember("showname") && value["showname"].IsString())
        {
            std::string showname = value["showname"].GetString();
            for (const auto& pair : translationMap)
            {
                const std::string& key         = pair.first;
                const std::string& translation = pair.second;

                if (showname.find(key) == 0)
                {
                    // 替换静态部分
                    showname.replace(0, key.length(), translation);
                    value["showname"].SetString(showname.c_str(), allocator);
                    break;
                }
            }
        }

        else if (value.HasMember("show") && value["show"].IsString())
        {
            std::string showname = value["show"].GetString();
            for (const auto& pair : translationMap)
            {
                const std::string& key         = pair.first;
                const std::string& translation = pair.second;

                // 检查字段A中是否包含translationMap中的key（静态部分）
                if (showname.find(key) == 0)
                {
                    // 替换静态部分
                    showname.replace(0, key.length(), translation);
                    value["show"].SetString(showname.c_str(), allocator);
                    break;
                }
            }
        }

        if (value.HasMember("field") && value["field"].IsArray())
        {
            // 直接引用 "field" 数组中的每个元素进行递归翻译
            for (rapidjson::Value& fieldArray = value["field"]; auto& field : fieldArray.GetArray())
            {
                TranslateShowNameFields(field, allocator); // 递归处理每个 field
            }
        }
    }
    else if (value.IsArray())
    {
        for (auto& item : value.GetArray())
        {
            TranslateShowNameFields(item, allocator); // 递归处理每个元素
        }
    }
}
