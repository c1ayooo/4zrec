package db

// 变更4（施工单-4zrec待办变更总表-20261014）：指纹 technologies 归一化。
//
// 问题：4zrecon 同步带入的 products（Wappalyzer/sas_ 命名）与本地 enrich 识别
// （dddd/wappalyzergo 命名）在 assets.technologies 里按 DISTINCT 并集累积，同一产品
// 以多套名字混存（"nginx"/"Nginx"/"nginx / 1.24"）。归一化 = 归命名空间，不归规则库。
//
// 设计（方案已认可）：
//   - 锚点最初定为 vulnkb 产品词表，实测 Go 侧无硬性产品名→漏洞匹配（联动走 agent
//     读 JSON），锚点退化为「出现频次最高的原始形态」——归一收益是数据卫生与 agent
//     阅读一致性，而非硬匹配命中率；
//   - 写侧归一唯一咽喉 = UpsertHTTPService（sync/enrich/agent-insert/REST 全部汇入）；
//   - 未知键 fail-open 原样透传并挂待归类行（canonical 空串），绝不丢名字；
//   - 首次调用一次性播种（assets 现量按频次取规范名）+ 存量回填一遍（settings 标记，
//     只跑一次）；人工修订 product_alias 表后可重跑 RewriteAssetsTechnologiesToCanonical。

import (
	"context"
	"strings"
	"sync"
	"time"
)

const productAliasSeededSetting = "product_alias_seeded"

// aliasKey 归一化键：小写 + 首尾空白 + 连续空白折叠（"Nginx " 与 "nginx" 同键）。
func aliasKey(raw string) string {
	return strings.Join(strings.Fields(strings.ToLower(raw)), " ")
}

// product_alias 表惰性建表：避免触碰 schema.sql 主迁移文件（该表自管理，
// CREATE IF NOT EXISTS 幂等）。每 DB 实例只执行一次。
var (
	paOnceMu sync.Mutex
	paOnce   = map[*DB]*sync.Once{}
)

func (d *DB) ensureProductAliasTable() {
	paOnceMu.Lock()
	once, ok := paOnce[d]
	if !ok {
		once = &sync.Once{}
		paOnce[d] = once
	}
	paOnceMu.Unlock()
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := d.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS product_alias (
			alias_key  text PRIMARY KEY,
			canonical  text NOT NULL DEFAULT '',
			source     text NOT NULL DEFAULT '',
			created_at timestamptz NOT NULL DEFAULT now()
		)`)
		if err != nil {
			// 建表失败（库暂不可用等）：下次调用重试（once 失败后重建）
			paOnceMu.Lock()
			delete(paOnce, d)
			paOnceMu.Unlock()
		}
	})
}

// ensureProductAliasSeeded 一次性播种：从 assets 现量按频次生成别名键 + 存量回填。
// settings 标记防重跑；失败不置标记（下次重试）。
func (d *DB) ensureProductAliasSeeded() {
	if _, ok, _ := d.GetSetting(productAliasSeededSetting); ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := d.BootstrapProductAliases(ctx); err != nil {
		return // 失败不置标记
	}
	if _, err := d.RewriteAssetsTechnologiesToCanonical(ctx); err != nil {
		return
	}
	_ = d.SetSetting(productAliasSeededSetting, time.Now().Format(time.RFC3339))
}

// NormalizeTechnologies 写侧归一：按别名表映射规范名并去重（保序）。
// 库不可用/无命中时原样透传——归一缺失不丢数据、不阻塞写入。
func (d *DB) NormalizeTechnologies(techs []string) []string {
	if len(techs) == 0 {
		return techs
	}
	d.ensureProductAliasTable()
	d.ensureProductAliasSeeded()

	keys := make([]string, 0, len(techs))
	seenKey := map[string]bool{}
	keyOf := make([]string, len(techs))
	for i, t := range techs {
		k := aliasKey(t)
		keyOf[i] = k
		if k != "" && !seenKey[k] {
			seenKey[k] = true
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return techs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := d.QueryContext(ctx,
		`SELECT alias_key, canonical FROM product_alias WHERE alias_key = ANY($1::text[])`,
		marshalStringArray(keys))
	if err != nil {
		return techs // fail-open
	}
	canonical := map[string]string{}
	for rows.Next() {
		var k, c string
		if err := rows.Scan(&k, &c); err != nil {
			continue
		}
		canonical[k] = c
	}
	rows.Close()

	out := make([]string, 0, len(techs))
	seenOut := map[string]bool{}
	var pending []string
	for i, t := range techs {
		k := keyOf[i]
		c, ok := canonical[k]
		if !ok {
			// 未知键：fail-open 透传 + 挂待归类行
			pending = append(pending, k)
			if !seenOut[t] {
				seenOut[t] = true
				out = append(out, t)
			}
			continue
		}
		if c == "" {
			// 待归类行（canonical 空）：透传原始形态
			if !seenOut[t] {
				seenOut[t] = true
				out = append(out, t)
			}
			continue
		}
		if !seenOut[c] {
			seenOut[c] = true
			out = append(out, c)
		}
	}
	if len(pending) > 0 {
		d.insertPendingAliases(pending)
	}
	return out
}

func (d *DB) insertPendingAliases(keys []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, k := range keys {
		_, _ = d.ExecContext(ctx,
			`INSERT INTO product_alias(alias_key, canonical, source) VALUES($1,'','autodetect') ON CONFLICT (alias_key) DO NOTHING`, k)
	}
}

// SetProductAlias 设置/修订一条别名映射（人工审核通道：canonical 置空即待归类）。
func (d *DB) SetProductAlias(alias, canonical, source string) error {
	d.ensureProductAliasTable()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := d.ExecContext(ctx,
		`INSERT INTO product_alias(alias_key, canonical, source) VALUES($1,$2,$3)
		 ON CONFLICT (alias_key) DO UPDATE SET canonical = EXCLUDED.canonical, source = EXCLUDED.source`,
		aliasKey(alias), strings.TrimSpace(canonical), source)
	return err
}

// BootstrapProductAliases 从 assets 现量播种别名键：每个归一键取出现频次最高的
// 原始形态为规范名（频次并列取字典序小者）。幂等（ON CONFLICT DO NOTHING）。
func (d *DB) BootstrapProductAliases(ctx context.Context) (int64, error) {
	d.ensureProductAliasTable()
	res, err := d.ExecContext(ctx, `
		INSERT INTO product_alias(alias_key, canonical, source)
		SELECT key, form, 'bootstrap' FROM (
			SELECT lower(trim(t)) AS key, trim(t) AS form, count(*) AS n,
			       row_number() OVER (PARTITION BY lower(trim(t)) ORDER BY count(*) DESC, trim(t) ASC) AS rn
			FROM assets, unnest(technologies) AS t
			WHERE trim(t) <> ''
			GROUP BY 1, 2
		) s
		WHERE rn = 1
		ON CONFLICT (alias_key) DO UPDATE
		SET canonical = EXCLUDED.canonical, source = 'bootstrap'
		WHERE product_alias.canonical = ''`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RewriteAssetsTechnologiesToCanonical 存量回填：把 assets.technologies 按别名表
// 重写为规范名（无映射的键原样保留）。幂等：IS DISTINCT FROM 保证只动有变化的行。
func (d *DB) RewriteAssetsTechnologiesToCanonical(ctx context.Context) (int64, error) {
	d.ensureProductAliasTable()
	res, err := d.ExecContext(ctx, `
		UPDATE assets SET technologies = sub.new_techs
		FROM (
			SELECT a.id AS asset_id,
			       ARRAY(SELECT DISTINCT COALESCE(NULLIF(pa.canonical, ''), t) FROM unnest(a.technologies) AS t
			             LEFT JOIN product_alias pa ON pa.alias_key = lower(trim(t))) AS new_techs
			FROM assets a
		) AS sub
		WHERE assets.id = sub.asset_id AND assets.technologies IS DISTINCT FROM sub.new_techs`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
