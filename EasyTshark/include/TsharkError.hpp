#pragma once
#include <map>
#include <string>

#define ERROR_SUCCESS           0
#define ERROR_PARAMETER_WRONG   1001
#define ERROR_INTERNAL_WRONG    1002
#define ERROR_DATABASE_WRONG    1003
#define ERROR_TSHARK_WRONG      1004
#define ERROR_STATUS_WRONG      1005
#define ERROR_FILE_TOO_LARGE     1006
#define ERROR_FILE_NOT_FOUND     1007
#define ERROR_FILE_SAVE_FAILED  1008

class TsharkError
{
public:
    static std::string GetErrorMsg(int errorCode)
    {
        if (ErrorMsgMap.contains(errorCode))
            return ErrorMsgMap[errorCode];
        return "未定义错误";
    }

private:
    inline static std::map<int, std::string> ErrorMsgMap = {
        { ERROR_SUCCESS, "操作成功" },
        { ERROR_PARAMETER_WRONG, "参数错误" },
        { ERROR_INTERNAL_WRONG, "内部错误" },
        { ERROR_DATABASE_WRONG, "数据库错误" },
        { ERROR_TSHARK_WRONG, "tshark执行错误" },
        { ERROR_STATUS_WRONG, "状态错误" },
        { ERROR_FILE_TOO_LARGE, "文件太大了" },
        { ERROR_FILE_NOT_FOUND, "文件不存在" }
    };
};
