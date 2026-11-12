package proxy

import (
	"bufio"
	"encoding/json"
	"math"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNetworkDifficultyFromBits(t *testing.T) {
	cases := []struct {
		name  string
		nbits string
		want  float64 // 0 — невалидный nbits
		coin  coinKind
	}{
		// Блок BTC 800000: сложность ≈ 5.36e13.
		{"btc block 800000", "17053894", 5.36e13, coinBTC},
		// diff1 по определению.
		{"diff1", "1d00ffff", 1, coinOther},
		// BCH-порядок (~6e11), LTC-порядок (~7e7).
		{"bch-like", "1801d4c0", 5.97e11, coinOther},
		{"ltc-like", "193d0900", 7.04e7, coinOther},
		{"short", "1705389", 0, coinOther},
		{"not hex", "zz053894", 0, coinOther},
		{"zero mantissa", "17000000", 0, coinOther},
		{"negative", "17853894", 0, coinOther},
	}
	for _, tc := range cases {
		got := networkDifficultyFromBits(tc.nbits)
		if tc.want == 0 {
			if got != 0 {
				t.Errorf("%s: ожидался 0, получено %g", tc.name, got)
			}
		} else if math.Abs(got-tc.want)/tc.want > 0.01 {
			t.Errorf("%s: сложность %g, ожидалась ≈%g", tc.name, got, tc.want)
		}
		if k := classifyCoin(got); k != tc.coin {
			t.Errorf("%s: монета %v, ожидалась %v", tc.name, k, tc.coin)
		}
	}
}

func TestNetworkDifficultyFromNotify(t *testing.T) {
	btc := `{"id":null,"method":"mining.notify","params":["j","p","c1","c2",[],"20000000","17053894","6500a1b2",true]}`
	if d, ok := NetworkDifficultyFromNotify([]byte(btc)); !ok || classifyCoin(d) != coinBTC {
		t.Fatalf("BTC notify не опознан: %g %v", d, ok)
	}
	// Не-биткоиновский формат (например, Kaspa: [job, [u64...], ts]).
	kas := `{"id":null,"method":"mining.notify","params":["j",[1,2,3,4],1700000000]}`
	if d, ok := NetworkDifficultyFromNotify([]byte(kas)); !ok || d != 0 {
		t.Fatalf("чужой формат notify должен давать 0: %g %v", d, ok)
	}
	if _, ok := NetworkDifficultyFromNotify([]byte(`{"id":1,"result":true}`)); ok {
		t.Fatal("ответ пула не notify")
	}
}

// Не-BTC шары видны в мониторинге, но не входят в базу бюджета комиссии.
func TestNonBTCWorkNotBillable(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats, WithBTCOnly())

	ltc := newSession(stats, "ltc:3333", "10.0.0.1", c)
	defer ltc.close()
	ltc.authorize("client.l7")
	ltc.setDifficulty(1000)
	ltc.observeNotify(7e7)
	ltc.submit(`1`, "client.l7")
	ltc.resolve(PoolResponse{ID: `1`, Accepted: true})

	btc := newSession(stats, "btc:3333", "10.0.0.2", c)
	defer btc.close()
	btc.authorize("client.s21")
	btc.setDifficulty(500)
	btc.observeNotify(1.4e14)
	btc.submit(`1`, "client.s21")
	btc.resolve(PoolResponse{ID: `1`, Accepted: true})

	if w := stats.AcceptedWork(); w != 500 {
		t.Fatalf("база бюджета должна включать только BTC: %g", w)
	}
	if a := stats.Accepted(); a != 2 {
		t.Fatalf("мониторинг должен видеть обе шары: %d", a)
	}
	coins := map[string]string{}
	for _, p := range stats.Report().Pools {
		coins[p.Pool] = p.Coin
	}
	if coins["ltc:3333"] != "other" || coins["btc:3333"] != "btc" {
		t.Fatalf("монеты пулов в /status: %v", coins)
	}

	// Без btcOnly облагается всё, как раньше.
	stats2 := NewStats()
	c2 := NewCommission("fee.worker", 2, 40, 0, 0, stats2)
	se := newSession(stats2, "ltc:3333", "10.0.0.1", c2)
	defer se.close()
	se.setDifficulty(1000)
	se.observeNotify(7e7)
	se.submit(`1`, "client.l7")
	se.resolve(PoolResponse{ID: `1`, Accepted: true})
	if w := stats2.AcceptedWork(); w != 1000 {
		t.Fatalf("без btcOnly работа должна облагаться: %g", w)
	}
}

// В режиме btcOnly соединение с не-BTC (или ещё не опознанной) монетой идёт
// прозрачно: ни служебного authorize, ни подмены воркера в submit.
func TestBTCOnlyCommissionGate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		netDiff float64 // < 0 — notify не было
		fee     bool
	}{
		{"unknown", -1, false},
		{"ltc", 7e7, false},
		{"bch", 6e11, false},
		{"btc", 1.4e14, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := NewStats()
			c := NewCommission("fee.worker", 2, 40, 0, 0, stats, WithBTCOnly())
			c.takeBudget = 1

			clientConn, minerSide := net.Pipe()
			defer clientConn.Close()
			defer minerSide.Close()
			dst, poolSide := net.Pipe()
			defer dst.Close()
			defer poolSide.Close()

			se := newSession(stats, "pool:3333", "10.0.0.1", c)
			se.setDifficulty(1)
			if tc.netDiff >= 0 {
				se.observeNotify(tc.netDiff)
			}
			defer se.close()

			go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)
			pr := bufio.NewReader(poolSide)
			send := func(s string) {
				if _, err := minerSide.Write([]byte(s + "\n")); err != nil {
					t.Fatalf("miner write: %v", err)
				}
			}
			recv := func() (method, worker string) {
				poolSide.SetReadDeadline(time.Now().Add(2 * time.Second))
				line, err := pr.ReadString('\n')
				if err != nil {
					t.Fatalf("pool read: %v", err)
				}
				var w struct {
					Method string            `json:"method"`
					Params []json.RawMessage `json:"params"`
				}
				if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &w); err != nil {
					t.Fatalf("unmarshal %q: %v", line, err)
				}
				json.Unmarshal(w.Params[0], &worker)
				return w.Method, worker
			}

			send(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
			recv()
			send(`{"id":2,"method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
			m, w := recv()
			if tc.fee {
				if m != "mining.authorize" || w != "fee.worker" {
					t.Fatalf("BTC: ожидался служебный authorize fee.worker, получено %s %s", m, w)
				}
				if m, w := recv(); m != "mining.submit" || w != "fee.worker" {
					t.Fatalf("BTC: ожидалась шара под fee.worker, получено %s %s", m, w)
				}
				// Дождаться регистрации шары до закрытия сессии.
				se.resolve(PoolResponse{ID: `2`, Accepted: true})
				return
			}
			if m != "mining.submit" || w != "client.w" {
				t.Fatalf("не-BTC: шара должна уйти без изменений, получено %s %s", m, w)
			}
		})
	}
}
