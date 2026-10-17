package vulnkb

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/4zrec/db"
)

// DefaultDir 是漏洞库源文件目录(相对工作目录)。仓库随二进制分发 vulnkb/,
// 与 skills/ 同级;可用 ZREC_VULNKB_DIR(旧名 ARTEX_VULNKB_DIR 回退)指向外部维护的库。
const DefaultDir = "vulnkb"

// ImportResult 汇总一次导入。
type ImportResult struct {
	Imported int // 新入库
	Skipped  int // content_hash 已存在
	Failed   int // 解析失败(计入日志,不中断)
}

// ImportDir 遍历目录下全部 .md,按 content_hash 幂等入库。目录不存在时静默
// 跳过(库是可选资产),返回 ok=false 表示本次没有可导入源。
func ImportDir(pg *db.DB, dir string) (ImportResult, bool) {
	res := ImportResult{}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return res, false
	}
	root := filepath.Clean(dir)
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 单目录失败继续走
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		entry, err := ParseFile(path)
		if err != nil {
			res.Failed++
			return nil
		}
		// source_path 存相对路径,库挪位置不产生伪差异。
		rel := strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(root)+"/")
		entry.SourcePath = rel
		if entry.Title == "" {
			res.Failed++
			return nil
		}
		inserted, err := pg.UpsertVulnKB(entry)
		if err != nil {
			res.Failed++
			log.Printf("[vulnkb] upsert %s: %v", rel, err)
			return nil
		}
		if inserted {
			res.Imported++
		} else {
			res.Skipped++
		}
		return nil
	})
	return res, true
}

// Bootstrap 在服务启动时后台导入一次。幂等(hash 命中即跳过),二次启动只付
// 一次目录遍历的成本(数千文件、秒级),换来「放好文件重启即入库」的零运维。
func Bootstrap(pg *db.DB, dir string) {
	go func() {
		res, ok := ImportDir(pg, dir)
		if !ok {
			log.Printf("[vulnkb] 目录 %s 不存在,跳过导入(可选资产)", dir)
			return
		}
		if res.Failed > 0 {
			log.Printf("[vulnkb] 导入完成: 新增 %d, 已存在 %d, 失败 %d", res.Imported, res.Skipped, res.Failed)
		} else {
			log.Printf("[vulnkb] 导入完成: 新增 %d, 已存在 %d", res.Imported, res.Skipped)
		}
	}()
}
