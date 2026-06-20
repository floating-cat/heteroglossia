package ss_carrier

import (
	"sync"
	"time"
)

// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
// Servers MUST store all incoming salts for 60 seconds.
// When a new TCP session is established, the first received message
// is decrypted and its timestamp MUST be checked against system time.
// If the time difference is within 30 seconds, then the salt is checked
// against all stored salts. If no repeated salt is discovered, then the
// salt is added to the pool and the session is successfully established.
type saltPool[T comparable] struct {
	pool        map[T]time.Time
	lastCleaned time.Time
	mutex       sync.Mutex
}

func newSaltPool[T comparable]() *saltPool[T] {
	return &saltPool[T]{pool: make(map[T]time.Time), lastCleaned: time.Now()}
}

const retainDuration = 60 * time.Second

// checkAndAdd atomically checks whether salt has been seen within retainDuration
// and, if not, records it. It returns true if the salt is new (no replay), false
// if the salt was already present (replay detected).
//
// The check and the insert are performed under a single lock acquisition so that
// two concurrent sessions presenting the same salt cannot both observe it as new
// before either records it (a Time-of-check to time-of-use race that would defeat replay protection).
func (p *saltPool[T]) checkAndAdd(salt T) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	now := time.Now()
	if now.Sub(p.lastCleaned) > retainDuration {
		for oldSalt, addedTime := range p.pool {
			if now.Sub(addedTime) > retainDuration {
				delete(p.pool, oldSalt)
			}
		}
		p.lastCleaned = now
	}
	_, ok := p.pool[salt]
	if ok {
		return false
	}
	p.pool[salt] = now
	return true
}
