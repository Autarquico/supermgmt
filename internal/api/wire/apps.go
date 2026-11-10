package wire

import (
	"net/url"
	"strings"
	"time"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// ---- apps: Compose projects on a node (spec app-panels, ADR-0043) -----------------------

const (
	PathNodeApps     = Prefix + "/nodes/{id}/apps"
	PathNodeApp      = Prefix + "/nodes/{id}/apps/{project}"
	PathNodeAppStats = Prefix + "/nodes/{id}/apps/{project}/stats"
	PathNodeAppLogs  = Prefix + "/nodes/{id}/apps/{project}/logs"
	PathApps         = Prefix + "/apps"
)

// Query parameters of the app reads.
const (
	QueryWithStats  = "stats"
	QueryWithErrors = "errors"
	QueryComponent  = "component"
	QuerySearch     = "search"
)

// App states: degraded is any component not running or unhealthy.
const (
	AppRunning  = "running"
	AppDegraded = "degraded"
)

// Problems that keep the apps of a node from being read live. Hint names what a person can do about it.
const (
	AppsProblemDocker      = "docker_unavailable"
	AppsProblemUnreachable = "node_unreachable"
)

// MaxAppLogLines is the most lines one app log read asks for; DefaultLogLines applies when it names none.
const MaxAppLogLines = 1000

// MaxSearchTermBytes bounds the term of a log search.
const MaxSearchTermBytes = 256

// ResourceUse is CPU and memory at the moment of a sample.
type ResourceUse struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemUsedBytes  uint64  `json:"mem_used_bytes"`
	MemLimitBytes uint64  `json:"mem_limit_bytes"`
}

// AppMount is a volume or bind mount of a component.
type AppMount struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"read_write"`
}

// AppConfig is the configuration the runtime reports for a component, redacted before it leaves the daemon:
// environment values by key, and credentials in commands, entrypoints and label values.
type AppConfig struct {
	RestartPolicy string            `json:"restart_policy"`
	Env           []string          `json:"env"`
	Command       []string          `json:"command"`
	Entrypoint    []string          `json:"entrypoint"`
	Labels        map[string]string `json:"labels"`
}

// AppComponent is one container of an app. RestartCount (lifetime, not a state) and the live fields are
// absent from a stale answer; RecentErrors is absent, not zero, for a caller without service.logs.
type AppComponent struct {
	Name         string       `json:"name"`
	ServiceID    domain.ID    `json:"service_id,omitempty"`
	Image        string       `json:"image"`
	Status       string       `json:"status"`
	Health       string       `json:"health"`
	StartedAt    string       `json:"started_at,omitempty"`
	RestartCount *int         `json:"restart_count,omitempty"`
	RecentErrors *int         `json:"recent_errors,omitempty"`
	Stats        *ResourceUse `json:"stats,omitempty"`
	Ports        []string     `json:"ports,omitempty"`
	Mounts       []AppMount   `json:"mounts,omitempty"`
	Config       *AppConfig   `json:"config,omitempty"`
}

// App is a Compose project of a node: a projection of what discovery stored, read live when it can be. A stale
// App is the last discovery, ReadAt being when it was seen.
type App struct {
	Project      string         `json:"project"`
	NodeID       domain.ID      `json:"node_id"`
	Node         string         `json:"node"`
	State        string         `json:"state"`
	RestartCount *int           `json:"restart_count,omitempty"`
	RecentErrors *int           `json:"recent_errors,omitempty"`
	Stats        *ResourceUse   `json:"stats,omitempty"`
	StatsAt      *time.Time     `json:"stats_at,omitempty"`
	ReadAt       time.Time      `json:"read_at"`
	Stale        bool           `json:"stale"`
	Components   []AppComponent `json:"components"`
	// Problem and Hint are set on the answer for one app only: why it could not be read live, as NodeApps
	// says it for the overview.
	Problem string `json:"problem,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

// OtherService is a service that belongs to no app: a container outside a Compose project or a unit.
type OtherService struct {
	ServiceID domain.ID `json:"service_id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	Health    string    `json:"health"`
}

// NodeApps is the apps of one node and its other services. Problem says why the apps could not be read live;
// the apps then are the last discovery, stale.
type NodeApps struct {
	NodeID        domain.ID      `json:"node_id"`
	Node          string         `json:"node"`
	Problem       string         `json:"problem,omitempty"`
	Hint          string         `json:"hint,omitempty"`
	Apps          []App          `json:"apps"`
	OtherServices []OtherService `json:"other_services"`
}

// ComponentUse is the resource use of one running component.
type ComponentUse struct {
	Name string      `json:"name"`
	Use  ResourceUse `json:"use"`
}

// AppStats answers GET /nodes/{id}/apps/{project}/stats: one sample, taken at SampledAt and stored nowhere.
type AppStats struct {
	Project    string         `json:"project"`
	NodeID     domain.ID      `json:"node_id"`
	SampledAt  time.Time      `json:"sampled_at"`
	Total      ResourceUse    `json:"total"`
	Components []ComponentUse `json:"components"`
}

// LogWindow says what a search covered: how many lines it read and the times of the first and the last.
type LogWindow struct {
	Lines int        `json:"lines"`
	From  *time.Time `json:"from,omitempty"`
	To    *time.Time `json:"to,omitempty"`
}

// AppLogs answers GET /nodes/{id}/apps/{project}/logs, credentials removed. Lines keep Docker's timestamp
// prefix. Cursor is opaque: pass it back to read what came after. Gap says lines were lost between two
// reads. A search carries Window and no Cursor.
type AppLogs struct {
	Project     string     `json:"project"`
	Component   string     `json:"component"`
	Lines       []string   `json:"lines"`
	Cursor      string     `json:"cursor,omitempty"`
	Gap         bool       `json:"gap"`
	Truncated   bool       `json:"truncated"`
	Window      *LogWindow `json:"window,omitempty"`
	CollectedAt time.Time  `json:"collected_at"`
}

// AppsQuery asks the app listings for live resource use and recent error counts.
type AppsQuery struct {
	Stats  bool
	Errors bool
}

// AppLogQuery is GET .../apps/{project}/logs. Lines 0 means DefaultLogLines. A Cursor follows; a Search
// searches a bounded window of recent lines; the two do not combine.
type AppLogQuery struct {
	Component string
	Lines     int
	Cursor    string
	Search    string
}

func (q AppsQuery) Values() url.Values {
	v := url.Values{}
	if q.Stats {
		v.Set(QueryWithStats, "true")
	}
	if q.Errors {
		v.Set(QueryWithErrors, "true")
	}
	return v
}

func (q AppLogQuery) Values() url.Values {
	v := url.Values{}
	setString(v, QueryComponent, q.Component)
	setInt(v, QueryLines, int64(q.Lines))
	setString(v, QueryCursor, q.Cursor)
	setString(v, QuerySearch, q.Search)
	return v
}

// ParseAppsQuery reads stats and errors, each true or false.
func ParseAppsQuery(v url.Values) (AppsQuery, error) {
	stats, err := boolParam(v, QueryWithStats)
	if err != nil {
		return AppsQuery{}, err
	}
	errs, err := boolParam(v, QueryWithErrors)
	return AppsQuery{Stats: stats, Errors: errs}, err
}

// ParseAppLogQuery reads the component, lines 0..MaxAppLogLines, cursor and search.
func ParseAppLogQuery(v url.Values) (AppLogQuery, error) {
	lines, err := smallIntParam(v, QueryLines, 0, MaxAppLogLines)
	if err != nil {
		return AppLogQuery{}, err
	}
	q := AppLogQuery{Component: v.Get(QueryComponent), Lines: lines, Cursor: v.Get(QueryCursor), Search: v.Get(QuerySearch)}
	if q.Cursor != "" && q.Search != "" {
		return AppLogQuery{}, smerr.New(smerr.CodeInvalidArgument, "", "cursor and search do not combine")
	}
	if len(q.Search) > MaxSearchTermBytes {
		return AppLogQuery{}, smerr.New(smerr.CodeInvalidArgument, "", "search term is too long")
	}
	return q, nil
}

func boolParam(v url.Values, key string) (bool, error) {
	switch strings.ToLower(v.Get(key)) {
	case "":
		return false, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, smerr.New(smerr.CodeInvalidArgument, "", "query parameter "+key+" must be true or false")
}
