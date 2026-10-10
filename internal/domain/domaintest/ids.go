package domaintest

import (
	"fmt"
	"sync"

	"github.com/autarquico/supermgmt/internal/domain"
)

// SequentialIDs issues deterministic, valid and time-ordered UUIDv7 values:
// the first is 00000000-0001-7000-8000-000000000000, then the 48-bit
// timestamp field counts up.
type SequentialIDs struct {
	mu   sync.Mutex
	next uint64
}

func NewSequentialIDs() *SequentialIDs { return &SequentialIDs{} }

func (s *SequentialIDs) NewID() domain.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return domain.ID(fmt.Sprintf("%08x-%04x-7000-8000-000000000000", s.next>>16, s.next&0xffff))
}
