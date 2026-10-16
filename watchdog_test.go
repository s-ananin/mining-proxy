package main

import "testing"

// Логика дебаунса: снятие правил — необратимо для майнеров (пока не вернём),
// поэтому срабатываем только после threshold подряд идущих неудач.
func TestWatchdogStateFlusesOnlyAfterThreshold(t *testing.T) {
	st := &watchdogState{threshold: 3}
	// Две неудачи подряд — ещё не снимаем.
	if act := st.observe(false); act != watchdogNone {
		t.Errorf("после 1-й неудачи хотели none, получили %v", act)
	}
	if act := st.observe(false); act != watchdogNone {
		t.Errorf("после 2-й неудачи хотели none, получили %v", act)
	}
	// Третья — порог, снимаем ровно один раз.
	if act := st.observe(false); act != watchdogFlush {
		t.Errorf("на пороге хотели flush, получили %v", act)
	}
	// Прокси всё ещё мёртв — повторно не снимаем.
	for i := 0; i < 5; i++ {
		if act := st.observe(false); act != watchdogNone {
			t.Errorf("повторная неудача не должна снова вызывать flush, получили %v", act)
		}
	}
}

// Ложное срабатывание: одиночный сбой (разовая таймаутная проверка) не должен
// приводить к снятию правил.
func TestWatchdogStateNoFlushOnIsolatedFailure(t *testing.T) {
	st := &watchdogState{threshold: 3}
	st.observe(true)
	if act := st.observe(false); act != watchdogNone {
		t.Errorf("одиночная неудача не должна снимать правила, получили %v", act)
	}
	// Следующая проверка живая — счётчик обнуляется.
	st.observe(true)
	if act := st.observe(false); act != watchdogNone {
		t.Errorf("после восстановления счётчик должен начаться заново, получили %v", act)
	}
}

// Восстановление: как только прокси снова слушает, правила возвращаются —
// один раз, без цикла «снял-вернул» при стабильном восстановлении.
func TestWatchdogStateRestoresOnce(t *testing.T) {
	st := &watchdogState{threshold: 2}
	st.observe(false)
	st.observe(false) // flush
	if act := st.observe(true); act != watchdogRestore {
		t.Errorf("после подъёма прокси хотели restore, получили %v", act)
	}
	// Прокси стабильно жив — правил больше не трогаем.
	for i := 0; i < 3; i++ {
		if act := st.observe(true); act != watchdogNone {
			t.Errorf("стабильная жизнь не должна повторять restore, получили %v", act)
		}
	}
}

// Цикл: снял → жив → снова мёртв — порог должен считаться заново, а flush
// снова срабатывать. Проверяет, что flushed корректно сбрасывается при restore.
func TestWatchdogStateCyclesCorrectly(t *testing.T) {
	st := &watchdogState{threshold: 2}
	st.observe(false)
	st.observe(false) // flush #1
	st.observe(true)  // restore
	if act := st.observe(false); act != watchdogNone {
		t.Errorf("после restore первая неудача не должна снимать, получили %v", act)
	}
	if act := st.observe(false); act != watchdogFlush {
		t.Errorf("на пороге во втором цикле хотели flush, получили %v", act)
	}
}

// probeAddr: слушатель на 0.0.0.0/:: должен проверяться по loopback, иначе
// Dial к 0.0.0.0 не пройдёт.
func TestProbeAddr(t *testing.T) {
	cases := []struct{ in, want string }{
		{"0.0.0.0:8443", "127.0.0.1:8443"},
		{"[::]:8443", "[::1]:8443"},
		{"127.0.0.1:8443", "127.0.0.1:8443"},
		{"192.168.1.5:8443", "192.168.1.5:8443"},
		{"[::1]:8443", "[::1]:8443"},
	}
	for _, c := range cases {
		if got := probeAddr(c.in); got != c.want {
			t.Errorf("probeAddr(%q) = %q, хотели %q", c.in, got, c.want)
		}
	}
}
