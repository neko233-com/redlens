package api

import (
	"log"
	"net/http"

	"github.com/redlens/redlens/internal/scanner"
)

type Server struct {
	engine *scanner.Engine
	mux    *http.ServeMux
}

func NewServer(engine *scanner.Engine) *Server {
	s := &Server{
		engine: engine,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/scanners", s.handleListScanners)
	s.mux.HandleFunc("POST /api/scan", s.handleScan)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
}

func (s *Server) Start(addr string) error {
	log.Printf("redlens API server starting on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}
