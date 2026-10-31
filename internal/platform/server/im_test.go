package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestImFeishuFrameRoundTrip(t *testing.T) {
	f := &imFeishuFrame{
		SeqID:   42,
		LogID:   7,
		Service: 101,
		Method:  1,
		Headers: []imFeishuHeader{
			{Key: "type", Value: "event"},
			{Key: "message_id", Value: "m-1"},
			{Key: "sum", Value: "1"},
			{Key: "seq", Value: "0"},
		},
		Payload: []byte(`{"schema":"2.0"}`),
	}
	raw := imFeishuFrameEncode(f)
	got, err := imFeishuFrameDecode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SeqID != f.SeqID || got.LogID != f.LogID || got.Service != f.Service || got.Method != f.Method {
		t.Fatalf("字段不回环: %+v vs %+v", got, f)
	}
	if len(got.Headers) != len(f.Headers) {
		t.Fatalf("header 数不一致: %d vs %d", len(got.Headers), len(f.Headers))
	}
	for i, h := range f.Headers {
		if got.Headers[i] != h {
			t.Fatalf("header[%d] 不一致: %+v vs %+v", i, got.Headers[i], h)
		}
	}
	if !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("payload 不一致: %q vs %q", got.Payload, f.Payload)
	}
}

// TestImFeishuFrameWireFormat 用手工按 protobuf wire 规则拼的字节校验编码器的
// 字段号/线型与官方 SDK 的 pbbp2.Frame 定义一致（SeqID=1 varint, LogID=2,
// Service=3, Method=4, Headers=5 rep, Payload=8 bytes）。
func TestImFeishuFrameWireFormat(t *testing.T) {
	f := &imFeishuFrame{SeqID: 1, LogID: 2, Service: 3, Method: 4,
		Headers: []imFeishuHeader{{Key: "k", Value: "v"}},
		Payload: []byte("hello")}
	raw := imFeishuFrameEncode(f)

	var expect bytes.Buffer
	putVarint := func(v uint64) {
		var tmp [binary.MaxVarintLen64]byte
		expect.Write(tmp[:binary.PutUvarint(tmp[:], v)])
	}
	putVarint(1<<3 | 0)
	putVarint(1)
	putVarint(2<<3 | 0)
	putVarint(2)
	putVarint(3<<3 | 0)
	putVarint(3)
	putVarint(4<<3 | 0)
	putVarint(4)
	// Header{Key:1, Value:2} 包装进 field 5
	var hb bytes.Buffer
	writeLenDelim := func(field int, s string) {
		var tmp [binary.MaxVarintLen64]byte
		hb.Write(tmp[:binary.PutUvarint(tmp[:], uint64(field)<<3|2)])
		hb.Write(tmp[:binary.PutUvarint(tmp[:], uint64(len(s)))])
		hb.WriteString(s)
	}
	writeLenDelim(1, "k")
	writeLenDelim(2, "v")
	putVarint(5<<3 | 2)
	putVarint(uint64(hb.Len()))
	expect.Write(hb.Bytes())
	putVarint(8<<3 | 2)
	putVarint(5)
	expect.WriteString("hello")

	if !bytes.Equal(raw, expect.Bytes()) {
		t.Fatalf("wire 格式与预期不一致:\n got %x\nwant %x", raw, expect.Bytes())
	}
}

// TestImWecomCryptRoundTrip 自加密→解密回环（加密侧按官方算法镜像实现）。
func TestImWecomCryptRoundTrip(t *testing.T) {
	aesKeyB64 := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" // 43 字符
	key, err := base64.StdEncoding.DecodeString(aesKeyB64 + "=")
	if err != nil || len(key) != 32 {
		t.Fatalf("测试用 key 非法: %v", err)
	}
	encrypt := func(plain []byte, receiveID string) string {
		// 官方算法：16B 随机 + 4B 大端长度 + 消息 + receiveid，整体按 32 字节块 PKCS7 填充。
		body := make([]byte, 0, 20+len(plain)+len(receiveID)+32)
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			t.Fatal(err)
		}
		body = append(body, rnd[:]...)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(plain)))
		body = append(body, lenBuf[:]...)
		body = append(body, plain...)
		body = append(body, []byte(receiveID)...)
		pad := 32 - len(body)%32
		for i := 0; i < pad; i++ {
			body = append(body, byte(pad))
		}
		block, _ := aes.NewCipher(key)
		out := make([]byte, len(body))
		cipher.NewCBCEncrypter(block, key[:16]).CryptBlocks(out, body)
		return base64.StdEncoding.EncodeToString(out)
	}

	msg := `<xml><FromUserName>zhangsan</FromUserName><MsgType>text</MsgType><Content>/bond</Content><MsgId>123</MsgId></xml>`
	enc := encrypt([]byte(msg), "corp123")
	sig := imWecomSignature("tok", "1700000000", "nonce1", enc)

	plain, err := imWecomDecrypt(aesKeyB64, sig, "tok", "1700000000", "nonce1", enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != msg {
		t.Fatalf("回环不一致:\n got %q\nwant %q", plain, msg)
	}

	// 篡改签名必须拒绝
	if _, err := imWecomDecrypt(aesKeyB64, "badbadbad", "tok", "1700000000", "nonce1", enc); err == nil {
		t.Fatal("错误签名应解密失败")
	}
}

func TestImTelegramNormalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/bond", "/bond"},
		{"/bond@MyBot", "/bond"},
		{"/bond@MyBot 虎牙", "/bond 虎牙"},
		{"/bond 虎牙", "/bond 虎牙"},
		{"普通消息", "普通消息"},
		{" /new ", "/new"},
	}
	for _, c := range cases {
		if got := imTelegramNormalize(c.in); got != c.want {
			t.Fatalf("imTelegramNormalize(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestImTruncateRunes(t *testing.T) {
	const marker = "\n…（已截断）"
	long := strings.Repeat("测", imTelegramMaxText+10)
	got := imTruncateRunes(long, imTelegramMaxText)
	if len([]rune(got)) != imTelegramMaxText+len([]rune(marker)) {
		t.Fatalf("截断后长度异常: %d", len([]rune(got)))
	}
	if !strings.HasSuffix(got, marker) {
		t.Fatal("缺少截断标记")
	}
	if imTruncateRunes("短文本", 100) != "短文本" {
		t.Fatal("短文本不应被截断")
	}
}

func TestImFeishuFrameDecodeRejectsGarbage(t *testing.T) {
	if _, err := imFeishuFrameDecode([]byte{0x0f, 0xff, 0xff}); err == nil {
		t.Fatal("垃圾字节应报错")
	}
}

func TestImFeishuCard(t *testing.T) {
	card := imFeishuCard("**绑定**：项目「虎牙src」")
	if card["msg_type"] != nil { // 卡片本身不含 msg_type（外层 body 才有）
		t.Fatal("卡片不应包含 msg_type")
	}
	elems, ok := card["elements"].([]any)
	if !ok || len(elems) != 1 {
		t.Fatalf("elements 异常: %#v", card["elements"])
	}
	div := elems[0].(map[string]any)
	text := div["text"].(map[string]any)
	if text["tag"] != "lark_md" {
		t.Fatalf("lark_md 缺失: %#v", text)
	}
	if !strings.Contains(text["content"].(string), "**绑定**") {
		t.Fatal("markdown 正文丢失")
	}
	// JSON 编码后是合法字符串（IM API 的 content 字段是卡片 JSON 的字符串形态）
	if _, err := json.Marshal(card); err != nil {
		t.Fatalf("卡片 JSON 编码失败: %v", err)
	}
}
