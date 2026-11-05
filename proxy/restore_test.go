package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRestoreRequiresAuthorizationAndJob(t *testing.T) {
	for _, notifyFirst := range []bool{false, true} {
		se := newSession(NewStats(), "pool", "miner", nil)
		se.setFeeActive(true)
		se.setJobID("fee-job")
		se.beginMinerRestore(nil)
		ack := []byte(`{"id":"__commission_restore__","result":true,"error":null}`)
		notify := []byte(`{"id":null,"method":"mining.notify","params":["original-job","p","c1","c2",[],"v","b","t",false],"extension":"preserved"}`)
		first, second := ack, notify
		if notifyFirst {
			first, second = notify, ack
		}
		handled, updates, err := se.restorePoolLine(first)
		if !handled || err != nil || len(updates) != 0 || !se.suppressDifficulty() {
			t.Fatalf("restore completed too early: %v", err)
		}
		if !se.oldCommissionShare([]byte(`{"method":"mining.submit","params":["w","fee-job"]}`)) {
			t.Fatal("old fee share allowed during restoration")
		}
		handled, updates, err = se.restorePoolLine(second)
		if !handled || err != nil || len(updates) != 1 || se.suppressDifficulty() {
			t.Fatalf("restore did not complete: %v", err)
		}
		if job, _ := JobIDFromNotify(updates[0]); job != "original-job" {
			t.Fatal("original job id changed")
		}
		var fields map[string]json.RawMessage
		json.Unmarshal(updates[0], &fields)
		var params []json.RawMessage
		json.Unmarshal(fields["params"], &params)
		if string(params[8]) != "true" || string(fields["extension"]) != `"preserved"` {
			t.Fatal("clean_jobs or extension lost")
		}
		se.close()
	}
}

func TestRestoreRejectsFailedAuthorization(t *testing.T) {
	se := newSession(NewStats(), "pool", "miner", nil)
	defer se.close()
	se.setFeeActive(true)
	se.beginMinerRestore(nil)
	_, _, err := se.restorePoolLine([]byte(`{"id":"__commission_restore__","result":false,"error":[24,"denied",null]}`))
	if err == nil || !se.suppressDifficulty() {
		t.Fatal("failed restore enabled miner mode")
	}
}

// Exercise the original two-pipe implementation for three fee windows on
// the same connection. The pool deliberately sends restore notify before
// authorize ack in alternating windows; a delayed fee-job submit is queued
// while the restore is pending. No aliases or automatic reconnects are used.
func TestImmediateMinerRestoreAcrossThreeWindows(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats)
	defer c.Close()
	se := newSession(stats, "pool", "miner", c)
	defer se.close()
	client, miner := net.Pipe()
	upstream, pool := net.Pipe()
	done := make(chan struct{}, 2)
	go func() { pipeMinerToPool(client, bufio.NewReader(client), upstream, se, c); done <- struct{}{} }()
	go func() { pipePoolToMiner(upstream, client, se); done <- struct{}{} }()
	defer func() {
		client.Close()
		miner.Close()
		upstream.Close()
		pool.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("pipe did not finish")
			}
		}
	}()
	minerReader, poolReader := bufio.NewReader(miner), bufio.NewReader(pool)
	write := func(conn net.Conn, raw string) {
		t.Helper()
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := writeLine(conn, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	read := func(conn net.Conn, reader *bufio.Reader) string {
		t.Helper()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(line)
	}
	notify := func(job string) string {
		return fmt.Sprintf(`{"id":null,"method":"mining.notify","params":[%q,"p","c1","c2",[],"v","b","t",false]}`, job)
	}
	submit := func(id int, job string) string {
		return fmt.Sprintf(`{"id":%d,"method":"mining.submit","params":["main.worker",%q,"e","t","n"]}`, id, job)
	}
	ack := func(id int) string { return fmt.Sprintf(`{"id":%d,"result":true,"error":null}`, id) }
	write(miner, `{"id":1,"method":"mining.authorize","params":["main.worker","x"]}`)
	read(pool, poolReader)
	write(pool, ack(1))
	read(miner, minerReader)
	write(pool, notify("initial"))
	read(miner, minerReader)
	job := "initial"
	for window := 0; window < 3; window++ {
		c.mu.Lock()
		c.takeBudget = 1
		c.mu.Unlock()
		c.authMu.Lock()
		c.lastAuth = time.Time{}
		c.authMu.Unlock()
		id := 10 + window*10
		write(miner, submit(id, job))
		if line := read(pool, poolReader); WorkerFromAuthorize([]byte(line)) != "fee.worker" {
			t.Fatalf("missing fee auth: %s", line)
		}
		write(pool, `{"id":"__commission_switch__","result":true,"error":null}`)
		if line := read(pool, poolReader); WorkerFromSubmit([]byte(line)) != "fee.worker" || submitJobID([]byte(line)) != job {
			t.Fatalf("original commission path changed: %s", line)
		}
		feeJob := fmt.Sprintf("fee-%d", window)
		write(pool, notify(feeJob))
		read(miner, minerReader)
		// Entering fee still uses the original throttle; restoring must not
		// queue behind it and wait for the next submit to initiate authorize.
		c.authMu.Lock()
		c.lastAuth = time.Now()
		c.authMu.Unlock()
		started := time.Now()
		write(pool, ack(id))
		read(miner, minerReader)
		line := read(pool, poolReader)
		msg, _ := Parse([]byte(line))
		if WorkerFromAuthorize([]byte(line)) != "main.worker" || string(msg.ID) != commissionRestoreID {
			t.Fatalf("missing immediate restore: %s", line)
		}
		if time.Since(started) >= time.Second {
			t.Fatal("restore queued behind auth throttle")
		}
		write(miner, submit(id+1, feeJob))
		response, ok := ParsePoolResponse([]byte(read(miner, minerReader)))
		if !ok || response.Accepted {
			t.Fatal("old fee-job share was falsely accepted")
		}
		job = fmt.Sprintf("main-%d", window)
		restoreAck := `{"id":"__commission_restore__","result":true,"error":null}`
		if window%2 != 0 {
			write(pool, restoreAck)
		}
		write(pool, `{"id":null,"method":"mining.set_difficulty","params":[32]}`)
		write(pool, `{"id":null,"method":"mining.set_extranonce","params":["01020304",8]}`)
		write(pool, notify(job))
		if window%2 == 0 {
			write(pool, restoreAck)
		}
		if line := read(miner, minerReader); !strings.Contains(line, "set_difficulty") {
			t.Fatalf("difficulty order: %s", line)
		}
		if line := read(miner, minerReader); !strings.Contains(line, "set_extranonce") {
			t.Fatalf("extranonce order: %s", line)
		}
		if line := read(miner, minerReader); func() bool { got, ok := JobIDFromNotify([]byte(line)); return ok && got == job }() == false {
			t.Fatalf("job changed: %s", line)
		}
		rawSubmit := submit(id+2, job)
		write(miner, rawSubmit)
		if line := read(pool, poolReader); line != rawSubmit {
			t.Fatalf("ordinary submit changed: %s", line)
		}
		write(pool, ack(id+2))
		read(miner, minerReader)
	}
	if report := c.Snapshot(); report.Accepted != 3 || report.Rejected != 0 || report.Failed != 0 {
		t.Fatalf("commission did not repeat: %+v", report)
	}
	if report := stats.Report(); report.Totals.Accepted != 3 || report.Totals.Rejected != 3 || report.Totals.Lost != 0 {
		t.Fatalf("incorrect ordinary/tail accounting: %+v", report.Totals)
	}
}
