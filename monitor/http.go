// Пакет monitor — HTTP-мониторинг: JSON-статистика шар и healthcheck.
//
// Эндпоинты:
//
//	/status — полный счёт шар (totals/пулы/воркеры + nat-диагностика);
//	/health — 200 ok, пока процесс жив (для скриптов и алертов).
//
// По умолчанию слушает 127.0.0.1 — наружу адрес не выставляйте:
// в /status видны IP майнеров и адреса пулов.
package monitor

import (
	"encoding/json"
	"log"
	"net/http"
)

// Snapshot возвращает готовый объект для сериализации в /status
// (в main подмешивается nat-диагностика). Функция, а не интерфейс:
// monitor не зависит от proxy/iptables, никаких циклических импортов.
type Snapshot func() interface{}

// Healthy — проверка живости процесса для /health.
type Healthy func() bool

// Handler возвращает http.Handler с /status и /health (вынесен отдельно
// от StartServer, чтобы тесты поднимали его через httptest).
func Handler(snapshot Snapshot, healthy Healthy) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(snapshot()); err != nil {
			log.Printf("[MONITOR] /status encode: %v", err)
		}
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if healthy != nil && !healthy() {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return mux
}

// StartServer поднимает HTTP-сервер в фоне (возврат немедленный).
func StartServer(addr string, snapshot Snapshot, healthy Healthy) {
	log.Printf("[MONITOR] http://%s/status", addr)
	go func() {
		if err := http.ListenAndServe(addr, Handler(snapshot, healthy)); err != nil {
			log.Printf("[MONITOR] http error: %v", err)
		}
	}()
}
