// Command shim is installed in the PVE host container under the names of the Proxmox tools (pct,
// pvesh, pveum, pvesm, pveam, pveversion). It forwards its argv and stdin to the pvesim controller
// in the test process and exits with the status the controller returns.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/autarquico/supermgmt/test/e2e/pvesim"
)

const configPath = "/etc/pvesim/controller.json"

type controller struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func main() {
	os.Exit(run())
}

func run() int {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fatal("read %s: %v", configPath, err)
	}
	var ctl controller
	if err := json.Unmarshal(raw, &ctl); err != nil {
		return fatal("decode %s: %v", configPath, err)
	}
	req := pvesim.Request{Tool: filepath.Base(os.Args[0]), Args: os.Args[1:], Stdin: readStdin()}
	body, _ := json.Marshal(req)
	resp, err := post(ctl, body)
	if err != nil {
		return fatal("pvesim controller unreachable: %v", err)
	}
	_, _ = os.Stdout.Write(resp.Stdout)
	_, _ = os.Stderr.Write(resp.Stderr)
	return resp.Code
}

func readStdin() []byte {
	if info, err := os.Stdin.Stat(); err != nil || info.Mode()&os.ModeCharDevice != 0 {
		return nil
	}
	data, _ := io.ReadAll(os.Stdin)
	return data
}

func post(ctl controller, body []byte) (pvesim.Response, error) {
	var last error
	for range 5 {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, ctl.URL+"/run", bytes.NewReader(body))
		if err != nil {
			return pvesim.Response{}, err
		}
		req.Header.Set("Authorization", "Bearer "+ctl.Token)
		resp, err := (&http.Client{Timeout: 15 * time.Minute}).Do(req)
		if err != nil {
			last = err
			time.Sleep(time.Second)
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			msg, _ := io.ReadAll(resp.Body)
			return pvesim.Response{}, fmt.Errorf("%s: %s", resp.Status, msg)
		}
		var out pvesim.Response
		return out, json.NewDecoder(resp.Body).Decode(&out)
	}
	return pvesim.Response{}, last
}

func fatal(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "pvesim shim: "+format+"\n", args...)
	return 255
}
