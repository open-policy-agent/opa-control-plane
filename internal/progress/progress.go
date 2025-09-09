package progress

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/schollz/progressbar/v3"
)

type Bar struct {
	pb *progressbar.ProgressBar
}

func (b *Bar) AddMax(m int) {
	if b == nil {
		return
	}
	b.pb.AddMax(m)
}

func (b *Bar) Add(n int) {
	if b == nil {
		return
	}
	_ = b.pb.Add(n)
}

func (b *Bar) Finish() {
	if b == nil {
		return
	}
	_ = b.pb.Finish()
}

func New(invisible bool, max int, desc string) *Bar {
	return &Bar{
		pb: progressbar.NewOptions64(
			int64(max),
			progressbar.OptionSetVisibility(!invisible),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionSetDescription(desc),
			progressbar.OptionSetElapsedTime(false),
			progressbar.OptionSetPredictTime(false),
			progressbar.OptionThrottle(65*time.Millisecond),
			progressbar.OptionSetRenderBlankState(true),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprint(os.Stderr, "\n")
			}),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionSetWidth(80),
			progressbar.OptionSetTheme(progressbar.ThemeASCII),
		),
	}
}

func Var(fs *pflag.FlagSet, yes *bool) {
	fs.BoolVarP(yes, "non-interactive", "", false, "Do not show progress meters")
}
