# Tomcat弱口令&&后台getshell

- **系统**：Tomcat　|　**类型**：默认口令　|　**CVE**：—

**请求体 / payload**
```
在 conf/tomcat-users.xml 文件中配置用户的权限和一个弱口令 tomcat/tomcat：
<tomcat-users>
<role rolename="manager-gui"/>
<role rolename="manager-script"/>
<role rolename="manager-jmx"/>
<role rolename="manager-status"/>
<role rolename="admin-gui"/>
<role rolename="admin-script"/>
<user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script"/>
</tomcat-users>
访问[http://192.168.110.49:8080/manager/html，输入用户名密码可进行后台部署war包getshell](http://192.168.110.49:8080/manager/html，输入用户名密码可进行后台部署war包getshell)
>
```

**其他**
- Tomcat 弱口令&& 后台getshell: + 漏洞简介
+ 漏洞复现
---