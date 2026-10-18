package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/c1ayooo/4zrec/internal/domain/db"
)

const maxTaskAssetRequestBytes = 512 << 10

func writeTaskAssetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrTaskAssetInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, db.ErrTaskAssetTaskNotFound), errors.Is(err, db.ErrTaskAssetAssetNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) attachTaskAssets(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTaskAssetRequestBytes)
	var request struct {
		AssetIDs      []int64            `json:"asset_ids"`
		SourceSummary string             `json:"source_summary"`
		Scope         companyScopeInputs `json:"scope"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	request.SourceSummary = strings.TrimSpace(request.SourceSummary)
	taskID, _ := parseTaskID(task.ID)
	if request.Scope != nil && len(request.AssetIDs) > 0 {
		writeErr(w, http.StatusBadRequest, "scope 与 asset_ids 不能同时提交")
		return
	}
	// 项目级 Key 只能挂本项目资产:否则可以把他项目/未归属资产的 id 挂到自己
	// 的任务上,再经 asset-refs 读到标签与类型。
	if scopeProject := scopedProjectID(r.Context()); scopeProject > 0 && len(request.AssetIDs) > 0 {
		outside, err := s.m.pg.AssetsNotOwnedByProject(request.AssetIDs, scopeProject)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(outside) > 0 {
			writeErr(w, http.StatusForbidden, "asset_ids 包含未归属本项目或他项目的资产")
			return
		}
	}
	if request.Scope != nil {
		// 任务作用域必须落在项目授权范围内;项目级 API Key 不能直接写 scope
		// (RegisterTaskAssetScopes 不走 fenceAgentScope,会把范围写出项目边界)。
		if !APIScopeFrom(r.Context()).Global {
			writeErr(w, http.StatusForbidden, "项目级 API Key 不能直接写任务作用域")
			return
		}
		mutation, err := s.m.Assets().RegisterTaskAssetScopes(taskID, request.Scope)
		if err != nil {
			writeTaskAssetError(w, err)
			return
		}
		task.Notify()
		writeJSON(w, http.StatusOK, mutation)
		return
	}
	mutation, err := s.m.Assets().AttachAssetsToTask(taskID, request.AssetIDs, request.SourceSummary)
	if err != nil {
		writeTaskAssetError(w, err)
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, mutation)
}

func (s *Server) detachTaskAsset(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	assetID, ok := pathInt(r, "assetID")
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad asset id")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	detached, err := s.m.Assets().DetachAssetFromTask(taskID, assetID)
	if err != nil {
		writeTaskAssetError(w, err)
		return
	}
	if !detached {
		writeErr(w, http.StatusNotFound, "asset is not associated with this task")
		return
	}
	task.Notify()
	writeJSON(w, http.StatusOK, map[string]any{"detached": assetID})
}

func (s *Server) taskIntentAssets(w http.ResponseWriter, r *http.Request) {
	task, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	taskID, _ := parseTaskID(task.ID)
	assets, err := s.m.Assets().IntentAssets(taskID)
	if err != nil {
		writeTaskAssetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": assets})
}
