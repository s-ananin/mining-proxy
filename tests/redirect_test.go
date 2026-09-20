package proxy_test

import (
	"testing"
	"time"

	"mining-proxy/proxy"
)

// TestShareStealerPassThrough проверяет pass-through режим: даже при
// percentage=100 и нулевых интервалах ни одна шара не «кусается»,
// но шары всё равно считаются в статистике total.
func TestShareStealerPassThrough(t *testing.T) {
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    1,
		TargetPool:   "127.0.0.1:9999",
		TargetWorker: "w",
		TargetPass:   "",
		PassThrough:  true,
	})
	defer stealer.Close()

	for i := 0; i < 50; i++ {
		if stealer.ShouldSteal() {
			t.Fatalf("share %d: pass-through must never steal", i)
		}
	}
	stolen, total := stealer.Stats()
	if stolen != 0 {
		t.Errorf("stolen = %d, want 0", stolen)
	}
	if total != 50 {
		t.Errorf("total = %d, want 50", total)
	}
}

func TestShareStealerNoStealBeforeInterval(t *testing.T) {
	// интервал большой, процент 100, но время паузы ещё не наступило
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		IntervalMin:  10 * time.Hour,
		IntervalMax:  10 * time.Hour,
		BatchSize:    3,
		TargetPool:   "127.0.0.1:9999",
		TargetWorker: "w",
		TargetPass:   "",
	})
	defer stealer.Close()

	// все шары пропускаются т.к. пауза до первого укуса ещё не вышла
	for i := 0; i < 10; i++ {
		if stealer.ShouldSteal() {
			t.Fatalf("share %d: should NOT steal before pause elapses", i)
		}
	}
}

func TestShareStealerStealsAtPercentage(t *testing.T) {
	// интервал 0 → пауза между укусами отсутствует, процент 100 →
	// укушена КАЖДАЯ шара (в среднем доля = percentage%).
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    3,
		TargetPool:   "127.0.0.1:9999",
		TargetWorker: "w",
		TargetPass:   "",
	})
	defer stealer.Close()

	stolen := 0
	for i := 0; i < 20; i++ {
		if stealer.ShouldSteal() {
			stolen++
		}
	}
	stolenStats, total := stealer.Stats()
	if stolenStats != stolen {
		t.Errorf("stats mismatch stolen=%d stolenStats=%d", stolen, stolenStats)
	}
	if total != 20 {
		t.Errorf("expected total 20, got %d", total)
	}
	if stolen != 20 {
		t.Errorf("expected all 20 stolen with 100%%, got %d", stolen)
	}
}

// TestShareStealerAchievesPercentage проверяет режим «пауза по времени»:
// при percentage=50 и большом потоке шар (без временной паузы) доля
// украденных стремится к ~50%.
func TestShareStealerAchievesPercentage(t *testing.T) {
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   50,
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    1,
		TargetPool:   "127.0.0.1:9999",
		TargetWorker: "w",
		TargetPass:   "",
	})
	defer stealer.Close()

	const n = 10000
	var stolen int
	for i := 0; i < n; i++ {
		if stealer.ShouldSteal() {
			stolen++
		}
	}
	pct := float64(stolen) / float64(n) * 100
	// 50% ± 3% (для n=10000 std ~0.5% — коридор с большим запасом)
	if pct < 47 || pct > 53 {
		t.Errorf("stolen percent = %.2f%%, want ~50%%", pct)
	}
}

// TestShareStealerPauseShares проверяет режим «паузы в шарах»: при
// percentage=20 кусаем 1 шару каждые 5 → доля украденных ≈ 20% ТОЧНО,
// независимо от временных интервалов (100/20 = 5 шар).
func TestShareStealerPauseShares(t *testing.T) {
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   20,
		IntervalMin:  10 * time.Hour, // игнорируется в этом режиме
		IntervalMax:  10 * time.Hour, // игнорируется
		BatchSize:    1,
		TargetPool:   "127.0.0.1:9999",
		TargetWorker: "w",
		TargetPass:   "",
		PauseShares:  true,
	})
	defer stealer.Close()

	const n = 100000
	var stolen int
	for i := 0; i < n; i++ {
		if stealer.ShouldSteal() {
			stolen++
		}
	}
	pct := float64(stolen) / float64(n) * 100
	// 20% ± 1% — режим должен быть точным
	if pct < 19 || pct > 21 {
		t.Errorf("pause-shares stolen percent = %.2f%%, want ~20%%", pct)
	}
}

// TestShareStealerAccepted тестирует учёт «выполненных» шар:
// счётчик accepted растёт ТОЛЬКО если целевой пул ответил result:true.
// result:false (reject) не засчитывается.
func TestShareStealerAccepted(t *testing.T) {
	// Целевой mock-пул: сначала reject, потом accept.
	targetPool := startMockPool(t)
	defer targetPool.Close()

	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    1,
		TargetPool:   targetPool.addr,
		TargetWorker: "w",
		TargetPass:   "",
	})
	defer stealer.Close()

	// Валидный mining.submit, который будем отправлять целевому пулу.
	submit := []byte(`{"id":1,"method":"mining.submit","params":["worker","job","extra","time","nonce"]}`)

	// 1) пул в режиме reject -> accepted не должен вырасти
	targetPool.setReject(true)
	if err := stealer.ForwardToTarget(submit); err != nil {
		t.Fatalf("forward (reject mode): %v", err)
	}
	if got := stealer.Accepted(); got != 0 {
		t.Errorf("accepted after reject: expected 0, got %d", got)
	}

	// 2) пул в режиме accept -> stepa принимается пропускаем != 0
	targetPool.setReject(false)
	if err := stealer.ForwardToTarget(submit); err != nil {
		t.Fatalf("forward (accept mode): %v", err)
	}
	if got := stealer.Accepted(); got != 1 {
		t.Errorf("accepted after accept: expected 1, got %d", got)
	}
}

// TestForwardToTargetFailover проверяет failover: если целевой пул
// недоступен, ForwardToTarget возвращает ошибку, но не паникует, а
// счётчик accepted не растёт. Майнинг реального пула при этом не
// прерывается (это видно в интеграционном тесте отдельно).
func TestForwardToTargetFailover(t *testing.T) {
	// Свободный порт — на него ничего не слушает, поэтому dial завершится
	// ошибкой (connection refused) быстро.
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    1,
		TargetPool:   "127.0.0.1:1", // порт 1 закрыт
		TargetWorker: "w",
		TargetPass:   "",
	})
	defer stealer.Close()

	submit := []byte(`{"id":1,"method":"mining.submit","params":["worker","job","extra","time","nonce"]}`)

	for i := 0; i < 3; i++ {
		if err := stealer.ForwardToTarget(submit); err == nil {
			t.Fatalf("iteration %d: expected error forwarding to dead pool, got nil", i)
		}
	}

	// Ни одна шара не принята.
	if got := stealer.Accepted(); got != 0 {
		t.Errorf("accepted: expected 0 (target dead), got %d", got)
	}
}
