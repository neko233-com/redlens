package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Engine struct {
	scanners map[string]Scanner
	mu       sync.RWMutex
}

func NewEngine() *Engine {
	return &Engine{
		scanners: make(map[string]Scanner),
	}
}

func (e *Engine) Register(s Scanner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scanners[s.Name()] = s
}

func (e *Engine) Run(ctx context.Context, name string, target *Target) (*Result, error) {
	e.mu.RLock()
	s, ok := e.scanners[name]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("scanner %q not found", name)
	}

	start := time.Now()
	result, err := s.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanner %s failed: %w", name, err)
	}
	result.Duration = time.Since(start)
	return result, nil
}

func (e *Engine) RunAll(ctx context.Context, targets []*Target) ([]*Result, error) {
	e.mu.RLock()
	var scanners []Scanner
	for _, s := range e.scanners {
		scanners = append(scanners, s)
	}
	e.mu.RUnlock()

	var results []*Result
	for _, target := range targets {
		for _, s := range scanners {
			start := time.Now()
			result, err := s.Scan(ctx, target)
			if err != nil {
				continue
			}
			result.Duration = time.Since(start)
			results = append(results, result)
		}
	}
	return results, nil
}

func (e *Engine) List() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var names []string
	for name := range e.scanners {
		names = append(names, name)
	}
	return names
}
