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
    for (rapidxml::xml_node<>* cur_node = node->first_node(); cur_node; cur_node = cur_node->next_sibling())
    {
        // 检查是否需要跳过节点
        rapidxml::xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
        if (hide_attr && std::string(hide_attr->value()) == "yes")
        {
            continue; // 如果 hide 属性值为 "true"，跳过该节点
        }

        // 检查是否已经有该节点名称的数组
        rapidjson::Value* array = nullptr;
        if (json.HasMember(cur_node->name()))
        {
            array = &json[cur_node->name()];
        }
        else
        {
            rapidjson::Value node_array(rapidjson::kArrayType); // 创建新的数组
            json.AddMember(rapidjson::Value(cur_node->name(), allocator).Move(), node_array, allocator);
            array = &json[cur_node->name()];
        }

        // 创建一个 JSON 对象代表当前节点
        rapidjson::Value child_json(rapidjson::kObjectType);

        // 处理节点的属性
        for (rapidxml::xml_attribute<>* attr = cur_node->first_attribute(); attr; attr = attr->next_attribute())
        {
            rapidjson::Value attr_name(attr->name(), allocator);
            rapidjson::Value attr_value(attr->value(), allocator);
            child_json.AddMember(attr_name, attr_value, allocator);
        }

        // 递归处理子节点
        XmlToJsonRecursive(child_json, cur_node, allocator);

        // 将当前节点对象添加到对应数组中
        array->PushBack(child_json, allocator);
    }
}
