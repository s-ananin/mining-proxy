// Файл coin.go — определение монеты соединения (BTC или нет).
//
// По договору комиссия берётся только с добычи BTC. Остальные монеты
// (BCH, LTC/DOGE на scrypt-ASIC, Kaspa и т.п.) проходят через прокси
// прозрачно: служебных authorize нет, их работа не входит в базу бюджета.
//
// Stratum V1 не сообщает монету явно, а пулы сидят на динамических IP,
// поэтому монета определяется по самому заданию: mining.notify несёт nbits
// (params[6]) — компактную цель сети. Сетевая сложность BTC (~1e14) на
// порядки выше, чем у любой другой монеты с тем же форматом заданий (BCH
// ~1e12, BSV ~1e11, LTC ~1e8, DOGE ~1e7). Всё, что не удалось уверенно
// опознать как BTC, считается «не BTC» — fail-open в пользу клиента.
package proxy

import (
	"encoding/hex"
	"math"
)

// btcMinNetworkDifficulty — порог сетевой сложности, выше которого задание
// считается биткоин-заданием. Сложность BTC превысила 1e13 в 2019 году и с
// тех пор только росла; ближайший SHA-256 конкурент (BCH) на два порядка ниже.
const btcMinNetworkDifficulty = 1e13

// coinKind — монета соединения по последнему mining.notify.
type coinKind int

const (
	coinUnknown coinKind = iota // notify ещё не было
	coinBTC
	coinOther
)

func (k coinKind) String() string {
	switch k {
	case coinBTC:
		return "btc"
	case coinOther:
		return "other"
	}
	return ""
}

// classifyCoin относит задание к монете по сетевой сложности из nbits.
// netDiff <= 0 — формат задания не биткоиновский (или nbits не разобран).
func classifyCoin(netDiff float64) coinKind {
	if netDiff >= btcMinNetworkDifficulty {
		return coinBTC
	}
	return coinOther
}

// networkDifficultyFromBits переводит compact nbits ("1703a30c") в сетевую
// сложность относительно diff1 = 0x00000000FFFF << 208 (как у bitcoind).
// Возвращает 0, если строка не является корректным nbits.
func networkDifficultyFromBits(nbits string) float64 {
	if len(nbits) != 8 {
		return 0
	}
	b, err := hex.DecodeString(nbits)
	if err != nil {
		return 0
	}
	exp := int(b[0])
	mant := float64(uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
	// Старший бит мантиссы — знак; отрицательная/нулевая цель невалидна.
	if mant == 0 || b[1]&0x80 != 0 || exp < 3 {
		return 0
	}
	// target = mant * 256^(exp-3); diff1 = 0xFFFF * 256^(0x1d-3).
	d := 0xFFFF / mant * math.Pow(256, float64(0x1d-exp))
	if math.IsInf(d, 0) || math.IsNaN(d) {
		return 0
	}
	return d
}
