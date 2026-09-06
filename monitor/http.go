// Пакет monitor — HTTP-мониторинг работы прокси.
//
// Слушает локальный адрес (по умолчанию 127.0.0.1:9090) и отдаёт
// два эндпоинта:
//   /status — JSON-статистика кражи шар (для оператора/интеграций);
//   /health — простой healthcheck («ok»), удобен для systemd/нагрузочных
//             проб и будущих интеграций.
//
// Мониторинг НЕ должен быть доступен наружу — только локально.
package monitor

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// StatsProvider — контракт, который должен реализовать ShareStealer,
// чтобы монитор мог получить статистику. Реализация в proxy/redirect.go.
type StatsProvider interface {
	Stats() (stolen, total int) // сколько украдено и всего шар
	Accepted() int              // сколько шар ПРИНЯТО целевым пулом
	ForwardFails() int          // сколько ошибок перенаправления (failover)
	TargetUp() bool             // доступен ли целевой пул (по health-check)
	Uptime() time.Duration      // время работы
	NextCycleIn() time.Duration // время до следующего «укуса»
}

// StatusResponse — структура JSON-ответа эндпоинта /status.
// Ключевой показатель для оператора — accepted_percent: доля шар, которые
// целевой пул РЕАЛЬНО принял (это и есть «выполненные» шары, комиссия).
type StatusResponse struct {
	StolenShares    int    `json:"stolen_shares"`    // сколько шар перенаправлено (попытки)
	TotalShares     int    `json:"total_shares"`     // сколько шар пришло всего
	StolenPercent   string `json:"stolen_percent"`   // % перенаправленных попыток (2 знака)
	AcceptedShares  int    `json:"accepted_shares"`  // сколько шар ПРИНЯТО целевым пулом
	AcceptedPercent string `json:"accepted_percent"` // % выполненных шар (принятых пулом)
	NextCycleIn     string `json:"next_cycle_in"`    // до следующего «укуса» (человекочитаемо)
	Uptime          string `json:"uptime"`           // uptime процесса
	TargetPool      string `json:"target_pool"`      // адрес целевого пула
	TargetWorker    string `json:"target_worker"`    // наш воркер на целевом пуле
	TargetUp        bool   `json:"target_up"`        // жив ли целевой пул (health-check)
	ForwardFails    int    `json:"forward_fails"`    // ошибок перенаправления (failover)
}

// StartServer регистрирует HTTP-обработчики и запускает сервер в фоне.
// Возвращает управление сразу (сервер работает в отдельной goroutine).
func StartServer(addr string, provider StatsProvider, targetPool, targetWorker string) {
	// Эндпоинт /status: отдаёт статистику в формате JSON.
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		// Берём актуальные счётчики из stealer (обёрнуты мьютексом).
		stolen, total := provider.Stats()
		accepted := provider.Accepted()

		// % перенаправленных попыток (все украденные, включая rejected).
		stolenPct := "0.00"
		if total > 0 {
			stolenPct = fmt.Sprintf("%.2f", float64(stolen)/float64(total)*100)
		}

		// % ВЫПОЛНЕННЫХ шар — только принятые целевым пулом.
		// Это и есть итоговая комиссия по договору.
		acceptedPct := "0.00"
		if total > 0 {
			acceptedPct = fmt.Sprintf("%.2f", float64(accepted)/float64(total)*100)
		}

		resp := StatusResponse{
			StolenShares:    stolen,
			TotalShares:     total,
			StolenPercent:   stolenPct,
			AcceptedShares:  accepted,
			AcceptedPercent: acceptedPct,
			NextCycleIn:     provider.NextCycleIn().Round(time.Second).String(),
			Uptime:          provider.Uptime().Round(time.Second).String(),
			TargetPool:      targetPool,
			TargetWorker:    targetWorker,
			TargetUp:        provider.TargetUp(),
			ForwardFails:    provider.ForwardFails(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Эндпоинт /health: всегда 200 OK, тело "ok".
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	log.Printf("[MONITOR] HTTP server on %s", addr)
	go func() {
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Printf("[MONITOR] HTTP error: %v", err)
		}
	}()
}
