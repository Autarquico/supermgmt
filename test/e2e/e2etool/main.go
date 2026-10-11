// Command e2etool is the two tiny servers the e2e tests run in containers: a TLS-terminating
// reverse proxy (what an operator puts in front of `sm server --tls proxy`) and a static file
// server over HTTPS (the release mirror). Standard library only.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: e2etool proxy|files [flags]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	listen := fs.String("listen", ":8443", "TLS listen address")
	cert := fs.String("cert", "", "certificate file")
	key := fs.String("key", "", "private key file")
	target := fs.String("target", "http://127.0.0.1:8787", "proxy: upstream URL")
	dir := fs.String("dir", "/srv", "files: directory to serve")
	_ = fs.Parse(os.Args[2:])

	var handler http.Handler
	switch os.Args[1] {
	case "proxy":
		handler = reverseProxy(*target)
	case "files":
		handler = http.FileServer(http.Dir(*dir))
	default:
		log.Fatal("unknown mode: use proxy or files")
	}
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

// reverseProxy forwards to target and states what the proxy knows: the client address and that
// TLS ended here. It overwrites whatever the client sent, as a real edge does.
func reverseProxy(target string) http.Handler {
	upstream, err := url.Parse(target)
	if err != nil {
		log.Fatal(err)
	}
	return &httputil.ReverseProxy{
		FlushInterval: -1, // server-sent events must not be buffered
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = r.In.Host
			r.Out.Header.Del("Forwarded")
			r.Out.Header.Set("X-Forwarded-For", clientIP(r.In.RemoteAddr))
			r.Out.Header.Set("X-Forwarded-Proto", "https")
			r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
		},
	}
}

func clientIP(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
