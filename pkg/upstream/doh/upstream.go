/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	defaultDoHTimeout = time.Second * 6
)

var nopLogger = zap.NewNop()

// Upstream is a DNS-over-HTTPS (RFC 8484) upstream.
type Upstream struct {
	rt          http.RoundTripper
	logger      *zap.Logger // non-nil
	urlTemplate *urlpkg.URL
	reqTemplate *http.Request
	usePost     bool
}

func NewUpstream(endPoint string, rt http.RoundTripper, logger *zap.Logger, usePOST bool) (*Upstream, error) {
	var req *http.Request
	var err error

	if usePOST {
		// POST模式：创建空请求体模板（后续填充DNS二进制数据）
		req, err = http.NewRequest(http.MethodPost, endPoint, nil)
		req.Header.Set("Content-Type", "application/dns-message") // 强制设置RFC要求的头
	} else {
		// GET模式：初始化dns=参数占位模板
		req, err = http.NewRequest(http.MethodGet, endPoint, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse http request, %w", err)
	}

	req.Header["Accept"] = []string{"application/dns-message"}
	req.Header["User-Agent"] = nil // Don't let go http send a default user agent header.

	if logger == nil {
		logger = nopLogger
	}
	return &Upstream{
		rt:          rt,
		logger:      logger,
		urlTemplate: req.URL,
		reqTemplate: req,
		usePost:     usePOST,
	}, nil
}

var (
	bufPool4k = pool.NewBytesBufPool(4096)
)
var (
	bufPoolget = pool.NewBytesBufPool(4096)
)

func (u *Upstream) ExchangeContext(ctx context.Context, q []byte) (*[]byte, error) {
	bp := pool.GetBuf(len(q))
	defer pool.ReleaseBuf(bp)
	wire := *bp
	copy(wire, q)

	// In order to maximize HTTP cache friendliness, DoH clients using media
	// formats that include the ID field from the DNS message header, such
	// as "application/dns-message", SHOULD use a DNS ID of 0 in every DNS
	// request.
	// https://tools.ietf.org/html/rfc8484#section-4.1
	wire[0] = 0
	wire[1] = 0

	type res struct {
		r   *[]byte
		err error
	}

	resChan := make(chan res, 1)
	go func() {
		// We overwrite the ctx with a fixed timeout context here.
		// Because the http package may close the underlay connection
		// if the context is done before the query is completed. This
		// reduces the connection reuse efficiency.
		ctx, cancel := context.WithTimeout(context.Background(), defaultDoHTimeout)
		defer cancel()
		r, err := u.exchange(ctx, wire)
		if err != nil {
			u.logger.Check(zap.WarnLevel, "exchange failed").Write(zap.Error(err))
		}
		resChan <- res{r: r, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case res := <-resChan:
		r := res.r
		err := res.err
		if r != nil {
			binary.BigEndian.PutUint16(*r, binary.BigEndian.Uint16(q))
		}
		return r, err
	}
}

func (u *Upstream) exchange(ctx context.Context, wire []byte) (*[]byte, error) {
	req := u.reqTemplate.WithContext(ctx)
	req.URL = new(urlpkg.URL)
	*req.URL = *u.urlTemplate
	if u.usePost { // POST 模式
		req.Body = io.NopCloser(bytes.NewReader(wire))
		req.ContentLength = int64(len(wire))
	} else {
		queryLen := 4 + base64.RawURLEncoding.EncodedLen(len(wire)) // "dns="前缀 + 编码后长度

		// 从bufPoolget获取缓冲区
		bb := bufPoolget.Get()
		defer bufPoolget.Release(bb)
		queryBuf := bb.Bytes()

		// 检查缓冲区容量是否足够
		if cap(queryBuf) < queryLen {
			// 不足时回退到临时分配（避免污染池）
			queryBuf = make([]byte, queryLen)
		} else {
			queryBuf = queryBuf[:queryLen]
		}
		p := copy(queryBuf, "dns=")

		// Padding characters for base64url MUST NOT be included.
		// See: https://tools.ietf.org/html/rfc8484#section-6.
		base64.RawURLEncoding.Encode(queryBuf[p:], wire)
		dnsQuery := utils.BytesToStringUnsafe(queryBuf)
		req.URL.RawQuery = dnsQuery
	}
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
	}()
	resp, err := u.rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	// check status code
	if resp.StatusCode != http.StatusOK {
		body1k, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if body1k != nil {
			return nil, fmt.Errorf("bad http status codes %d with body [%s]", resp.StatusCode, body1k)
		}
		return nil, fmt.Errorf("bad http status codes %d", resp.StatusCode)
	}

	bb := bufPool4k.Get()
	defer bufPool4k.Release(bb)
	_, err = bb.ReadFrom(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read http body: %w", err)
	}
	if bb.Len() < dnsutils.DnsHeaderLen {
		return nil, dnsutils.ErrPayloadTooSmall
	}
	payload := pool.GetBuf(bb.Len())
	copy(*payload, bb.Bytes())
	return payload, nil
}
