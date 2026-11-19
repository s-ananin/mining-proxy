// Пакет monitor — HTTP-мониторинг: JSON-статистика шар и healthcheck.
//
// Эндпоинты:
//
//	/status — полный счёт шар (totals/пулы/воркеры + nat-диагностика);
//	/health — 200 ok, пока процесс жив (для скриптов и алертов);
//	/port-info — порты пулов: что идёт через DNAT в прокси, что мимо
//	          (подключается в main через Endpoint).
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

// Endpoint — дополнительный JSON-эндпоинт (например /port-info).
type Endpoint struct {
	Path     string
	Snapshot Snapshot
}

// Handler возвращает http.Handler с /status, /health и доп. эндпоинтами
// (вынесен отдельно от StartServer, чтобы тесты поднимали его через httptest).
func Handler(snapshot Snapshot, healthy Healthy, extra ...Endpoint) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", jsonHandler("/status", snapshot))
	for _, ep := range extra {
		mux.HandleFunc(ep.Path, jsonHandler(ep.Path, ep.Snapshot))
	}

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

// jsonHandler отдаёт снимок как форматированный JSON.
func jsonHandler(path string, snapshot Snapshot) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(snapshot()); err != nil {
			log.Printf("[MONITOR] %s encode: %v", path, err)
		}
	}
}

// StartServer поднимает HTTP-сервер в фоне (возврат немедленный).
func StartServer(addr string, snapshot Snapshot, healthy Healthy, extra ...Endpoint) {
	log.Printf("[MONITOR] http://%s/status", addr)
	go func() {
		if err := http.ListenAndServe(addr, Handler(snapshot, healthy, extra...)); err != nil {
			log.Printf("[MONITOR] http error: %v", err)
		}
	}()
}
