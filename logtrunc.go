package main

import (
	"log"
	"os"
	"time"
)

// startStdoutTruncation раз в every обрезает до нуля файл, в который
// перенаправлены stdout/stderr (nohup.out при запуске через nohup или
// "> file 2>&1"). Терминал, pipe и journald (systemd) не трогаются —
// только обычный файл. Возвращает функцию остановки.
//
// Почему безопасно на ходу: nohup открывает nohup.out с O_APPEND, и после
// Truncate(0) следующая запись идёт с нового конца файла. Если файл открыт
// без O_APPEND ("> file"), смещение дескриптора осталось бы прежним и файл
// стал бы «дырявым» на исходный размер — поэтому дополнительно Seek(0):
// stdout и stderr при "2>&1" делят одно открытое описание файла, смещение
// у них общее. Записи, попавшие между Truncate и Seek, могут потеряться —
// для логов это допустимо.
func startStdoutTruncation(every time.Duration) func() {
	if every <= 0 {
		return func() {}
	}
	files := regularOutputs()
	if len(files) == 0 {
		return func() {}
	}
	log.Printf("[MAIN] stdout в файле — очистка раз в %s", every)

	done := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				for _, f := range files {
					truncateOutput(f)
				}
				log.Printf("[MAIN] лог-файл очищен (следующая очистка через %s)", every)
			}
		}
	}()
	return func() { close(done) }
}

// regularOutputs возвращает stdout/stderr, указывающие на обычные файлы,
// без дублей (при "2>&1" это один и тот же файл).
func regularOutputs() []*os.File {
	var out []*os.File
	var seen []os.FileInfo
	for _, f := range []*os.File{os.Stdout, os.Stderr} {
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		dup := false
		for _, s := range seen {
			if os.SameFile(s, fi) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		seen = append(seen, fi)
		out = append(out, f)
	}
	return out
}

func truncateOutput(f *os.File) {
	if err := f.Truncate(0); err != nil {
		log.Printf("[MAIN] очистка лог-файла %s: %v", f.Name(), err)
		return
	}
	// Для O_APPEND смещение не важно; для "> file" — вернуть в начало.
	_, _ = f.Seek(0, 0)
}
