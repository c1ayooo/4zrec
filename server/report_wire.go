package server

import (
	"context"
	"errors"
	"log"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"github.com/Autumn-27/artex/report"
)

// wireReport 把报告子系统接进宿主:注入单次补全实现(激活 LLM profile,低温
// 度有界输出,与拦截裁判同一范式),并把报告 skill 骨架落到 skill 目录(只写
// 缺失文件,内置默认是 single source of truth,用户编辑永不覆盖)。
func (s *Server) wireReport(skillDir string) {
	report.CompleteFunc = func(ctx context.Context, system, user string, maxTokens int) (string, error) {
		p, err := s.m.PG().ActiveProfile()
		if err != nil || p == nil {
			return "", errReportNoProfile
		}
		prov, _, ok := s.providerForProfile(p.ID)
		if !ok {
			return "", errReportNoProfile
		}
		msg, err := prov.Generate(ctx,
			[]*schema.Message{schema.SystemMessage(system), schema.UserMessage(user)},
			model.WithMaxTokens(maxTokens),
			model.WithTemperature(0),
		)
		if err != nil {
			return "", err
		}
		return msg.Content, nil
	}
	if err := report.SeedSkillFiles(skillDir); err != nil {
		log.Printf("[report] 报告 skill 骨架落盘失败(用内置默认): %v", err)
	}
}

var errReportNoProfile = errors.New("no active LLM profile")
