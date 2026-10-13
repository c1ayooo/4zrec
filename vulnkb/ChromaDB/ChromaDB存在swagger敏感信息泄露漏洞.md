# ChromaDB存在swagger敏感信息泄露漏洞

ChromaDB ｜ 信息泄露 ｜ —
- **指纹**：`Chroma`
- **请求**：`GET /api/v1/collections?tenant=default_tenant&database=default_database`

**Payload**
```
GET /api/v2/tenants/default_tenant/databases/default_database/collections
GET /docs（Swagger UI）
GET /openapi.json（OpenAPI规范）
```
- **响应特征**：200 [{
  "id": "7c807fbe-9717-4b44-8a06-046106554183",
  "name": "knowledge_base",
  "configuration_json": {"hnsw_configuration":{"space":"l2","ef_construction":100