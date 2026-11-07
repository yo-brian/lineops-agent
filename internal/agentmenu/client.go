// Package agentmenu provides a root-operated client using the VPS-scoped Agent
// identity. It never edits sing-box config directly or creates admin sessions.
package agentmenu

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"lineops-agent/internal/agentproto"
)

type object map[string]any
type panelClient struct {
	origin string
	token  string
	http   *http.Client
}

func newClient(origin, ca string) (*panelClient, error) {
	u, err := url.Parse(strings.TrimRight(origin, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("面板地址必须是 HTTPS 域名，不能带路径或账号")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		pem, e := os.ReadFile(ca)
		if e != nil {
			return nil, e
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA 文件无效")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return &panelClient{origin: u.String(), http: &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("面板重定向已拒绝，请使用正确的面板主域名")
	}}}, nil
}

func (p *panelClient) call(method, path string, body any, out any) error {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	prefix := "/api/v1/agent/menu"
	req, err := http.NewRequest(method, p.origin+prefix+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Origin", p.origin)
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	}
	key := ""
	if method != "GET" {
		key = agentproto.ID()
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("请求未确认，写操作请先到面板查看任务，勿直接重复提交（请求编号 %s）：%w", key, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return errors.New("面板响应过大，操作结果需到面板核实")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var v struct {
			Error struct {
				Message string `json:"message"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(b, &v)
		if resp.StatusCode == 401 {
			p.token = ""
		}
		return fmt.Errorf("面板请求未完成（HTTP %d，请求编号 %s）：%s", resp.StatusCode, key, clean(v.Error.Message))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (p *panelClient) nodes(group string) ([]object, error) {
	var items []object
	for page := 1; page <= 100000; page++ {
		var result struct {
			Items []object `json:"items"`
			Total *int     `json:"total"`
		}
		path := fmt.Sprintf("/groups/%s/nodes?page=%d&page_size=100", group, page)
		if err := p.call("GET", path, nil, &result); err != nil {
			return nil, err
		}
		if len(result.Items) > 100 {
			return nil, errors.New("节点分页响应超出范围")
		}
		items = append(items, result.Items...)
		if result.Total == nil || page*100 >= *result.Total {
			return items, nil
		}
		if len(result.Items) == 0 {
			return nil, errors.New("节点列表已变化，请刷新后重新选择")
		}
	}
	return nil, errors.New("节点分页超出范围，请在面板缩小范围")
}

func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}
func str(v any) string {
	if v == nil {
		return ""
	}
	return clean(fmt.Sprint(v))
}
