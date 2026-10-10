package wire

import (
	"net/url"
	"strconv"

	"github.com/autarquico/supermgmt/internal/domain"
	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Query parameter names.
const (
	QueryCursor       = "cursor"
	QueryLimit        = "limit"
	QueryFocus        = "focus"
	QueryLines        = "lines"
	QueryState        = "state"
	QueryEnvironment  = "environment"
	QueryTag          = "tag"
	QueryReachability = "reachability"
	QueryResourceType = "resource_type"
	QueryResourceID   = "resource_id"
	QueryAfterSeq     = "after_seq"
)

// Page sizes.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// DefaultLogLines is used when a logs request names no line count.
const DefaultLogLines = 200

// PageQuery selects one page of a list. Limit 0 means DefaultLimit.
type PageQuery struct {
	Cursor string
	Limit  int
}

// NodeQuery filters GET /nodes. Empty fields do not filter.
type NodeQuery struct {
	PageQuery
	Environment  string
	Tag          string
	Reachability domain.Reachability
}

// JobQuery filters GET /jobs by state; no states means every state.
type JobQuery struct {
	PageQuery
	States []domain.JobState
}

// EventQuery filters GET /events. AfterSeq returns events with a greater seq,
// which is how pollers follow the log until SSE arrives (M2).
type EventQuery struct {
	PageQuery
	ResourceType domain.ResourceType
	ResourceID   domain.ID
	AfterSeq     int64
}

// LogQuery is GET /services/{id}/logs. Lines 0 means DefaultLogLines.
type LogQuery struct {
	Lines int
}

func (q PageQuery) Values() url.Values {
	v := url.Values{}
	setString(v, QueryCursor, q.Cursor)
	setInt(v, QueryLimit, int64(q.Limit))
	return v
}

func (q NodeQuery) Values() url.Values {
	v := q.PageQuery.Values()
	setString(v, QueryEnvironment, q.Environment)
	setString(v, QueryTag, q.Tag)
	setString(v, QueryReachability, string(q.Reachability))
	return v
}

func (q JobQuery) Values() url.Values {
	v := q.PageQuery.Values()
	for _, s := range q.States {
		v.Add(QueryState, string(s))
	}
	return v
}

func (q EventQuery) Values() url.Values {
	v := q.PageQuery.Values()
	setString(v, QueryResourceType, string(q.ResourceType))
	setString(v, QueryResourceID, string(q.ResourceID))
	setInt(v, QueryAfterSeq, q.AfterSeq)
	return v
}

func (q LogQuery) Values() url.Values {
	v := url.Values{}
	setInt(v, QueryLines, int64(q.Lines))
	return v
}

// ParsePageQuery reads cursor and limit; the limit must be 0..MaxLimit.
func ParsePageQuery(v url.Values) (PageQuery, error) {
	limit, err := intParam(v, QueryLimit, 0, MaxLimit)
	if err != nil {
		return PageQuery{}, err
	}
	return PageQuery{Cursor: v.Get(QueryCursor), Limit: int(limit)}, nil
}

func ParseNodeQuery(v url.Values) (NodeQuery, error) {
	page, err := ParsePageQuery(v)
	if err != nil {
		return NodeQuery{}, err
	}
	q := NodeQuery{PageQuery: page, Environment: v.Get(QueryEnvironment), Tag: v.Get(QueryTag)}
	if r := v.Get(QueryReachability); r != "" {
		if q.Reachability, err = domain.ParseReachability(r); err != nil {
			return NodeQuery{}, err
		}
	}
	return q, nil
}

func ParseJobQuery(v url.Values) (JobQuery, error) {
	page, err := ParsePageQuery(v)
	if err != nil {
		return JobQuery{}, err
	}
	q := JobQuery{PageQuery: page}
	for _, s := range v[QueryState] {
		state, err := domain.ParseJobState(s)
		if err != nil {
			return JobQuery{}, err
		}
		q.States = append(q.States, state)
	}
	return q, nil
}

func ParseEventQuery(v url.Values) (EventQuery, error) {
	page, err := ParsePageQuery(v)
	if err != nil {
		return EventQuery{}, err
	}
	q := EventQuery{PageQuery: page}
	if t := v.Get(QueryResourceType); t != "" {
		if q.ResourceType, err = domain.ParseResourceType(t); err != nil {
			return EventQuery{}, err
		}
	}
	if id := v.Get(QueryResourceID); id != "" {
		if q.ResourceID, err = domain.ParseID(id); err != nil {
			return EventQuery{}, err
		}
	}
	if q.AfterSeq, err = intParam(v, QueryAfterSeq, 0, 1<<62); err != nil {
		return EventQuery{}, err
	}
	return q, nil
}

// ParseLogQuery reads lines, 0..10000 (spec §16 bound).
func ParseLogQuery(v url.Values) (LogQuery, error) {
	lines, err := intParam(v, QueryLines, 0, 10000)
	return LogQuery{Lines: int(lines)}, err
}

func setString(v url.Values, key, value string) {
	if value != "" {
		v.Set(key, value)
	}
}

func setInt(v url.Values, key string, value int64) {
	if value != 0 {
		v.Set(key, strconv.FormatInt(value, 10))
	}
}

func intParam(v url.Values, key string, lowest, highest int64) (int64, error) {
	raw := v.Get(key)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < lowest || n > highest {
		return 0, smerr.New(smerr.CodeInvalidArgument, "",
			"query parameter "+key+" must be an integer between "+strconv.FormatInt(lowest, 10)+" and "+strconv.FormatInt(highest, 10))
	}
	return n, nil
}
