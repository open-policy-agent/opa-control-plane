package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

type Logger struct {
	l *slog.Logger
}

type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo // Default (0)
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type Config struct {
	Level Level
}

func NewLogger(config Config) *Logger {
	return &Logger{
		l: slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: config.Level,
		})),
	}
}

func (l *Logger) Debug(msg string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Debug]
	r := slog.NewRecord(time.Now(), slog.LevelDebug, msg, pcs[0])
	r.Add(args...)
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Debugf(format string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Debugf]
	r := slog.NewRecord(time.Now(), slog.LevelDebug, fmt.Sprintf(format, args...), pcs[0])
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Info(msg string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelInfo) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Info]
	r := slog.NewRecord(time.Now(), slog.LevelInfo, msg, pcs[0])
	r.Add(args...)
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Infof(format string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelInfo) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), slog.LevelInfo, fmt.Sprintf(format, args...), pcs[0])
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Warn(msg string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelWarn) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Warn]
	r := slog.NewRecord(time.Now(), slog.LevelWarn, msg, pcs[0])
	r.Add(args...)
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Warnf(format string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelWarn) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Warnf]
	r := slog.NewRecord(time.Now(), slog.LevelWarn, fmt.Sprintf(format, args...), pcs[0])
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Error(msg string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelError) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Error]
	r := slog.NewRecord(time.Now(), slog.LevelError, msg, pcs[0])
	r.Add(args...)
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Errorf(format string, args ...any) {
	if l == nil || !l.l.Enabled(context.Background(), slog.LevelError) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Errorf]
	r := slog.NewRecord(time.Now(), slog.LevelError, fmt.Sprintf(format, args...), pcs[0])
	_ = l.l.Handler().Handle(context.Background(), r)
}

func (l *Logger) Fatal(msg string, args ...any) {
	if l == nil {
		os.Exit(1)
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Error]
	r := slog.NewRecord(time.Now(), slog.LevelError, msg, pcs[0])
	r.Add(args...)
	_ = l.l.Handler().Handle(context.Background(), r)
	os.Exit(1)
}

func (l *Logger) Fatalf(format string, args ...any) {
	if l == nil {
		os.Exit(1)
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Errorf]
	r := slog.NewRecord(time.Now(), slog.LevelError, fmt.Sprintf(format, args...), pcs[0])
	_ = l.l.Handler().Handle(context.Background(), r)
	os.Exit(1)
}

func VarP(cmd *cobra.Command, config *Config) {
	logLevels := map[Level][]string{
		LevelDebug: {"debug"},
		LevelInfo:  {"info"},
		LevelWarn:  {"warn"},
		LevelError: {"error"},
	}

	cmd.Flags().VarP(
		enumflag.New(&config.Level, "log-level", logLevels, enumflag.EnumCaseSensitive),
		"log-level", "", "set log level (debug, info, warn, error)")
}
