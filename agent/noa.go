package agent

import (
	"log"
	"path/filepath"

	"github.com/Autumn-27/artex/askernel"
	"github.com/Autumn-27/artex/noa"
)

// noaWarn returns a diagnostics sink tagging non-fatal noa messages with the
// session, routed through the package logger (agents have no per-instance one).
func noaWarn(session string) func(string) {
	return func(msg string) { log.Printf("[noa] %s: %s", session, msg) }
}

// noa 是平台的「模型驱动上下文压缩」实验功能,由用户在系统设置中开关。它与内置
// compaction 互斥:noa.Enable 是唯一入口,一次挂上上下文接管器(Takeover)、Compress
// 工具与三段常驻提示词,不调用 Enable 即为关闭(内置 compaction 照常工作)。开关由
// 每个 agent 注入的 noaEnabledFn 解析,每 run 读一次,故切换只影响之后启动的 run,
// 无需重建 agent。

// enableNoa 在解析器报告开启时把 noa 接入 opts。archiveRoot 是压缩原文的持久化基目录
// (取全局 workDir,各 agent 统一落在 <workDir>/noa 下,不随任务/意图目录分散),sessionID
// 命名其下的归档子目录(全局唯一,故同一基目录内不冲突)。
//
// noa 是实验功能:接入失败不得中断真实任务。发生错误时经 onWarn 上报并回退内置压缩。
// 启用成功时清掉 opts.Compaction,避免内核因「两个上下文管理器同时设置」告警。
// 压缩压力阈值沿用内置 compaction 的上下文窗口配置(无则用 noa 的保守默认)。
func enableNoa(opts *askernel.Options, enabled func() bool, archiveRoot, sessionID string, onWarn func(string)) {
	if enabled == nil || !enabled() {
		return
	}
	if opts.OnWarn == nil {
		opts.OnWarn = onWarn
	}
	noaOpts := noa.Options{
		ArchiveBaseDir: filepath.Join(archiveRoot, "noa"),
		SessionID:      sessionID,
		OnWarn:         onWarn,
	}
	if opts.Compaction != nil && opts.Compaction.ContextWindow > 0 {
		noaOpts.ModelContextLimit = opts.Compaction.ContextWindow
	}
	if err := noa.Enable(opts, noaOpts); err != nil {
		if onWarn != nil {
			onWarn("noa 压缩启用失败,回退内置压缩:" + err.Error())
		}
		return
	}
	// Takeover 覆盖 Compaction,但两者并存时内核每次会告警;明确清掉。
	opts.Compaction = nil
}
