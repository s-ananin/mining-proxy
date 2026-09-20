package proxy

import (
	"testing"
	"time"
)

// TestStealRulesMatch проверяет семантику allowlist:
// пусто = разрешено всё; pool без worker = все воркеры; pool+worker = точная пара.
func TestStealRulesMatch(t *testing.T) {
	// Правила не заданы — legacy-режим, разрешено всё.
	var empty *StealRules
	if !empty.Match("1.2.3.4:3333", "вася3344") {
		t.Fatal("nil rules should match everything")
	}
	if !NewStealRules(nil).Match("any:1", "any") {
		t.Fatal("empty rules should match everything")
	}

	rules := NewStealRules([]StealRule{
		{Pool: "1.2.3.4:3333"},                     // все воркеры пула
		{Pool: "5.6.7.8:3333", Worker: "вася3344"}, // только конкретный воркер
	})

	// pool-only правило матчит любого воркера, в т.ч. пустого.
	for _, w := range []string{"вася3344", "петя", ""} {
		if !rules.Match("1.2.3.4:3333", w) {
			t.Fatalf("pool-only rule should match worker %q", w)
		}
	}
	// pool+worker матчит только точную пару.
	if !rules.Match("5.6.7.8:3333", "вася3344") {
		t.Fatal("pool+worker rule should match exact pair")
	}
	if rules.Match("5.6.7.8:3333", "петя") {
		t.Fatal("pool+worker rule must not match another worker")
	}
	// Пул вне списка — сквозняк.
	if rules.Match("9.9.9.9:3333", "вася3344") {
		t.Fatal("unlisted pool must not match")
	}
	if got := rules.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
}

// TestShouldStealForRules проверяет, что не попавшие в allowlist шары не
// кусаются, но всё равно учитываются в общей статистике (totalCount).
func TestShouldStealForRules(t *testing.T) {
	rules := NewStealRules([]StealRule{
		{Pool: "1.2.3.4:3333", Worker: "вася3344"},
	})
	s := NewShareStealer(&ShareStealerConfig{
		Percentage:    100, // каждый подходящий submit кусаем
		PauseShares:   true,
		IntervalMin:   time.Hour,
		IntervalMax:   2 * time.Hour,
		BatchSize:     1,
		TargetPool:    "127.0.0.1:1",
		TargetWorker:  "w",
		TargetPass:    "x",
		TargetTimeout: 50 * time.Millisecond,
		Rules:         rules,
	})
	defer s.Close()

	if !s.ShouldStealFor("1.2.3.4:3333", "вася3344") {
		t.Fatal("listed pool+worker should be stolen")
	}
	if s.ShouldStealFor("1.2.3.4:3333", "петя") {
		t.Fatal("another worker of same pool must not be stolen")
	}
	if s.ShouldStealFor("9.9.9.9:3333", "вася3344") {
		t.Fatal("unlisted pool must not be stolen")
	}

	stolen, total := s.Stats()
	if stolen != 1 {
		t.Fatalf("stolen = %d, want 1", stolen)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3 (all submits counted)", total)
	}
}

// TestShouldStealForPoolOnly проверяет правило только с пулом: кусаются ВСЕ
// воркеры этого пула, включая ещё не авторизованного (пустое имя).
func TestShouldStealForPoolOnly(t *testing.T) {
	s := NewShareStealer(&ShareStealerConfig{
		Percentage:    100,
		PauseShares:   true,
		IntervalMin:   time.Hour,
		IntervalMax:   2 * time.Hour,
		BatchSize:     1,
		TargetPool:    "127.0.0.1:1",
		TargetWorker:  "w",
		TargetPass:    "x",
		TargetTimeout: 50 * time.Millisecond,
		Rules:         NewStealRules([]StealRule{{Pool: "1.2.3.4:3333"}}),
	})
	defer s.Close()

	for _, w := range []string{"вася3344", "петя", ""} {
		if !s.ShouldStealFor("1.2.3.4:3333", w) {
			t.Fatalf("pool-only rule should steal worker %q", w)
		}
	}
	if s.ShouldStealFor("9.9.9.9:3333", "вася3344") {
		t.Fatal("unlisted pool must not be stolen")
	}
	if stolen, total := s.Stats(); stolen != 3 || total != 4 {
		t.Fatalf("stats = %d/%d, want 3/4", stolen, total)
	}
}
