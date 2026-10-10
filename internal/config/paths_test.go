package config

import "testing"

func TestResolve(t *testing.T) {
	const home = "/home/u"
	tests := []struct {
		name string
		goos string
		env  map[string]string
		want Paths
	}{
		{
			name: "linux without XDG variables",
			goos: "linux",
			want: Paths{
				Config:   "/home/u/.config/supermgmt/config.yaml",
				DataDir:  "/home/u/.local/share/supermgmt",
				DB:       "/home/u/.local/share/supermgmt/supermgmt.db",
				StateDir: "/home/u/.local/state/supermgmt",
				Socket:   "/home/u/.local/state/supermgmt/run/sm.sock",
			},
		},
		{
			name: "linux with every XDG variable",
			goos: "linux",
			env: map[string]string{
				"XDG_CONFIG_HOME": "/x/config", "XDG_DATA_HOME": "/x/data",
				"XDG_STATE_HOME": "/x/state", "XDG_RUNTIME_DIR": "/run/user/1000",
			},
			want: Paths{
				Config:   "/x/config/supermgmt/config.yaml",
				DataDir:  "/x/data/supermgmt",
				DB:       "/x/data/supermgmt/supermgmt.db",
				StateDir: "/x/state/supermgmt",
				Socket:   "/run/user/1000/supermgmt/sm.sock",
			},
		},
		{
			name: "linux with only XDG_STATE_HOME falls back to the state dir for the socket",
			goos: "linux",
			env:  map[string]string{"XDG_STATE_HOME": "/x/state"},
			want: Paths{
				Config:   "/home/u/.config/supermgmt/config.yaml",
				DataDir:  "/home/u/.local/share/supermgmt",
				DB:       "/home/u/.local/share/supermgmt/supermgmt.db",
				StateDir: "/x/state/supermgmt",
				Socket:   "/x/state/supermgmt/run/sm.sock",
			},
		},
		{
			name: "relative and empty XDG values count as unset",
			goos: "linux",
			env:  map[string]string{"XDG_CONFIG_HOME": "relative/dir", "XDG_RUNTIME_DIR": ""},
			want: Paths{
				Config:   "/home/u/.config/supermgmt/config.yaml",
				DataDir:  "/home/u/.local/share/supermgmt",
				DB:       "/home/u/.local/share/supermgmt/supermgmt.db",
				StateDir: "/home/u/.local/state/supermgmt",
				Socket:   "/home/u/.local/state/supermgmt/run/sm.sock",
			},
		},
		{
			name: "darwin without XDG variables",
			goos: "darwin",
			want: Paths{
				Config:   "/home/u/Library/Application Support/SuperMgmt/config.yaml",
				DataDir:  "/home/u/Library/Application Support/SuperMgmt",
				DB:       "/home/u/Library/Application Support/SuperMgmt/supermgmt.db",
				StateDir: "/home/u/Library/Application Support/SuperMgmt/state",
				Socket:   "/home/u/Library/Application Support/SuperMgmt/state/run/sm.sock",
			},
		},
		{
			name: "darwin honors XDG variables exactly as linux",
			goos: "darwin",
			env: map[string]string{
				"XDG_CONFIG_HOME": "/x/config", "XDG_DATA_HOME": "/x/data", "XDG_STATE_HOME": "/x/state",
			},
			want: Paths{
				Config:   "/x/config/supermgmt/config.yaml",
				DataDir:  "/x/data/supermgmt",
				DB:       "/x/data/supermgmt/supermgmt.db",
				StateDir: "/x/state/supermgmt",
				Socket:   "/x/state/supermgmt/run/sm.sock",
			},
		},
		{
			name: "darwin mixes XDG and Application Support per variable",
			goos: "darwin",
			env:  map[string]string{"XDG_CONFIG_HOME": "/x/config"},
			want: Paths{
				Config:   "/x/config/supermgmt/config.yaml",
				DataDir:  "/home/u/Library/Application Support/SuperMgmt",
				DB:       "/home/u/Library/Application Support/SuperMgmt/supermgmt.db",
				StateDir: "/home/u/Library/Application Support/SuperMgmt/state",
				Socket:   "/home/u/Library/Application Support/SuperMgmt/state/run/sm.sock",
			},
		},
		{
			name: "darwin ignores XDG_RUNTIME_DIR for the socket",
			goos: "darwin",
			env:  map[string]string{"XDG_RUNTIME_DIR": "/run/user/501"},
			want: Paths{
				Config:   "/home/u/Library/Application Support/SuperMgmt/config.yaml",
				DataDir:  "/home/u/Library/Application Support/SuperMgmt",
				DB:       "/home/u/Library/Application Support/SuperMgmt/supermgmt.db",
				StateDir: "/home/u/Library/Application Support/SuperMgmt/state",
				Socket:   "/home/u/Library/Application Support/SuperMgmt/state/run/sm.sock",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.goos, tt.env, home); got != tt.want {
				t.Errorf("Resolve() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestServerPaths(t *testing.T) {
	p := ServerPaths()
	if p.Config != "/etc/supermgmt/config.yaml" || p.DB != "/var/lib/supermgmt/supermgmt.db" {
		t.Errorf("ServerPaths() = %+v", p)
	}
}
