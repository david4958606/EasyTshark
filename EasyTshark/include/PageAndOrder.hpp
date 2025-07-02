#pragma once
#include <string>

class PageAndOrder
{
public:
    void Reset()
    {
        PageNum  = 0;
        PageSize = 0;
        OrderBy.clear();
        DescOrAsc.clear();
    }

    int         PageNum  = 0;
    int         PageSize = 0;
    std::string OrderBy;
    std::string DescOrAsc;
};

class PageHelper
{
public:
    static PageAndOrder* GetPageAndOrder()
    {
        return &PageAndOrder;
    }

    static std::string GetPageSql()
    {
        std::stringstream ss;
        if (!PageAndOrder.OrderBy.empty())
        {
            ss << " ORDER BY " << PageAndOrder.OrderBy << " " << PageAndOrder.DescOrAsc;
        }
        const int offset = (PageAndOrder.PageNum - 1) * PageAndOrder.PageSize;
        ss << " LIMIT " << PageAndOrder.PageSize << " OFFSET " << offset << ";";

        return ss.str();
    }

private:
    inline static thread_local PageAndOrder PageAndOrder;
};
