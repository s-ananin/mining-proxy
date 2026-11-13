package proxy

import "time"

const (
	normalAccepted = iota
	normalRejected
	feeAccepted
	feeRejected
	historySeconds = 24 * 60 * 60
)

// AverageReport contains accepted work and rejected work, all expressed in TH/s.
// Ordinary pools exclude commission, which is reported separately.
type AverageReport struct {
	PoolsTHs            float64 `json:"pools_ths"`
	CommissionTHs       float64 `json:"commission_ths"`
	PoolsRejectTHs      float64 `json:"pools_reject_ths"`
	CommissionRejectTHs float64 `json:"commission_reject_ths"`
}

type workBucket struct {
	second int64
	work   [4]float64
}

// One global ring, independent of the number of workers and share frequency.
// One-second buckets keep a full day of history with bounded memory.
type workHistory struct{ buckets []workBucket }

func (h *workHistory) add(now time.Time, kind int, diff float64) {
	if diff <= 0 {
		return
	}
	if h.buckets == nil {
		h.buckets = make([]workBucket, historySeconds+1)
	}
	second := now.Unix()
	b := &h.buckets[second%int64(len(h.buckets))]
	if b.second != second {
		*b = workBucket{second: second}
	}
	b.work[kind] += diff
}

func (h *workHistory) report(start, now time.Time) map[string]AverageReport {
	windows := [...]time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour}
	names := [...]string{"10m", "60m", "24h"}
	sums := [3][4]float64{}
	for _, b := range h.buckets {
		age := now.Sub(time.Unix(b.second, 0))
		if age < 0 {
			continue
		}
		for i, window := range windows {
			if age >= window {
				continue
			}
			for k, work := range b.work {
				sums[i][k] += work
			}
		}
	}
	result := make(map[string]AverageReport, len(windows))
	for i, window := range windows {
		elapsed := now.Sub(start)
		if elapsed > window {
			elapsed = window
		}
		var rates [4]float64
		if elapsed > 0 {
			for k, work := range sums[i] {
				rates[k] = work * diffToHash / elapsed.Seconds() / 1e12
			}
		}
		result[names[i]] = AverageReport{rates[0], rates[2], rates[1], rates[3]}
	}
	return result
}
