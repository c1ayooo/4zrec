package icp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"sort"
	"strings"
)

// matchSliderOffset 定位滑块验证码在大图中的缺口横坐标（原图尺度）。
//
// 算法（对齐原 Rust/Python 实现）：
//  1. 读小图尺寸得到缺口边长与左侧跳过区；
//  2. 大图 2x 下采样，颜色量化到 4bit/通道并打包成离散色号；
//  3. 统计色号直方图，取出现次数最多的前 3 种颜色当作候选背景色；
//  4. 对每种候选色构造前景掩膜，按列求竖直连续段长度；
//  5. 自上而下扫描，寻找近正方形（宽高比 0.7~1.4）且面积最大的连通段；
//  6. 命中面积达到阈值即可提前结束，返回 best_x*2（补偿下采样）。
func matchSliderOffset(smallB64, bigB64 string) (int, error) {
	smallBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(smallB64))
	if err != nil {
		return 0, fmt.Errorf("小图 base64 解码失败: %w", err)
	}
	bigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bigB64))
	if err != nil {
		return 0, fmt.Errorf("大图 base64 解码失败: %w", err)
	}

	smallImg, err := png.Decode(bytes.NewReader(smallBytes))
	if err != nil {
		return 0, fmt.Errorf("小图 PNG 解码失败: %w", err)
	}
	sw, sh := smallImg.Bounds().Dx(), smallImg.Bounds().Dy()
	if sw == 0 || sh == 0 {
		return 0, fmt.Errorf("小图尺寸无效")
	}

	bigImg, err := png.Decode(bytes.NewReader(bigBytes))
	if err != nil {
		return 0, fmt.Errorf("大图 PNG 解码失败: %w", err)
	}
	bb := bigImg.Bounds()
	bw, bh := bb.Dx(), bb.Dy()
	if bw == 0 || bh == 0 {
		return 0, fmt.Errorf("大图尺寸无效")
	}

	// 统一转成 RGBA 以便按步长直接取像素。
	rgba := image.NewRGBA(image.Rect(0, 0, bw, bh))
	draw.Draw(rgba, rgba.Bounds(), bigImg, bb.Min, draw.Src)

	w, h := bw/2, bh/2
	if w == 0 || h == 0 {
		return 0, fmt.Errorf("大图下采样后尺寸无效")
	}

	side := sw
	if sh < side {
		side = sh
	}
	minSide := int(float32(side) * 0.25)
	if minSide < 1 {
		minSide = 1
	}
	skipLeft := sw / 4
	goodEnough := minSide * minSide * 3 / 2

	// 下采样 + 量化（4bit/通道）。
	colorID := make([]uint32, w*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*2)*rgba.Stride + (x*2)*4
			q0 := uint32((rgba.Pix[i] >> 2) << 2)
			q1 := uint32((rgba.Pix[i+1] >> 2) << 2)
			q2 := uint32((rgba.Pix[i+2] >> 2) << 2)
			colorID[y*w+x] = q0 | (q1 << 8) | (q2 << 16)
		}
	}

	// 直方图，取前 3 高频色。
	counts := make(map[uint32]int, 128)
	for _, c := range colorID {
		counts[c]++
	}
	type bucket struct {
		color uint32
		n     int
	}
	ranked := make([]bucket, 0, len(counts))
	for c, n := range counts {
		ranked = append(ranked, bucket{c, n})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].n > ranked[j].n })
	topN := len(ranked)
	if topN > 3 {
		topN = 3
	}
	if topN == 0 {
		return 0, fmt.Errorf("未找到缺口")
	}

	bestArea, bestX := 0, 0
	mask := make([]byte, w*h)
	colRun := make([]int, w*h)

	for t := 0; t < topN; t++ {
		target := ranked[t].color
		for i, c := range colorID {
			if c == target {
				mask[i] = 1
			} else {
				mask[i] = 0
			}
		}

		// 每列自上而下的连续段长度。
		for x := 0; x < w; x++ {
			colRun[x] = int(mask[x])
		}
		for y := 1; y < h; y++ {
			row, prev := y*w, (y-1)*w
			for x := 0; x < w; x++ {
				if mask[row+x] != 0 {
					colRun[row+x] = colRun[prev+x] + 1
				} else {
					colRun[row+x] = 0
				}
			}
		}

		for y := minSide; y < h; y++ {
			row := y * w
			for x := skipLeft; x < w; {
				if colRun[row+x] < minSide {
					x++
					continue
				}
				start := x
				for x < w && colRun[row+x] >= minSide {
					x++
				}
				runW := x - start
				runH := colRun[row+start]
				if runH <= 0 {
					continue
				}
				ratio := float32(runW) / float32(runH)
				area := runW * runH
				if ratio >= 0.7 && ratio < 1.4 && area > bestArea {
					bestArea = area
					bestX = start
					if bestArea >= goodEnough {
						return bestX * 2, nil
					}
				}
			}
		}
	}

	if bestArea == 0 {
		return 0, fmt.Errorf("未找到缺口")
	}
	return bestX * 2, nil
}
