package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Yanliangchan/unpackr/assets"
	"github.com/Yanliangchan/unpackr/internal/artvault"
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/internal/safety"
	"github.com/Yanliangchan/unpackr/internal/terminal"
	"github.com/Yanliangchan/unpackr/internal/version"
	"github.com/Yanliangchan/unpackr/internal/worker"
)

// optionalTools are probed for presence only. No adapter exists yet, so being
// installed changes nothing in this build; doctor says so.
var optionalTools = []struct{ name, bin, role string }{
	{"UPX", "upx", "unpacking"},
	{"YARA-X", "yr", "signature engine"},
	{"Rizin", "rizin", "disassembly / function analysis"},
	{"Ghidra (headless)", "analyzeHeadless", "decompilation"},
	{"capa", "capa", "capability detection"},
	{"FLOSS", "floss", "obfuscated strings"},
	{"Detect It Easy", "diec", "packer/compiler second opinion"},
	{"ILSpy", "ilspycmd", ".NET decompilation"},
	{"7-Zip", "7zz", "archive extraction"},
	{"unblob", "unblob", "container extraction"},
}

func newDoctorCmd(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the installation, sandbox and optional tools",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := g.loadConfig()
			if err != nil {
				return err
			}
			g.maybeBanner(cmd, cfg, false)
			out := cmd.OutOrStdout()
			st := terminal.Style{On: terminal.ColorEnabled(os.Stdout, g.noColor)}
			ok, bad := st.Green("ok"), st.Red("PROBLEM")
			row := func(k, v string) { fmt.Fprintf(out, "  %-18s %s\n", k, v) }

			fmt.Fprintln(out, st.Bold("UNPACKR doctor"))
			row("Version", version.Version)
			row("Platform", version.Platform())
			row("Network", "none used (only a loopback probe inside the sandbox self-test)")
			row("Config dir", config.Dir())

			v, warns, lerr := artvault.Load(assets.ArtVault, "artvault", customArtDir())
			if lerr != nil {
				row("ArtVault", bad+": "+lerr.Error())
			} else {
				row("ArtVault", fmt.Sprintf("%s: %d banners, %d custom file(s) rejected", ok, len(v.All()), len(warns)))
			}

			fmt.Fprintln(out, "\n"+st.Bold("Sandbox (a worker process is started and probed)"))
			res, werr := worker.Run(context.Background(), engine.TaskSelfTest, nil, nil, 0, worker.Options{
				Timeout:          30 * time.Second,
				MemoryLimitBytes: uint64(cfg.WorkerMemoryMB) << 20,
			})
			if werr != nil && res == nil {
				row("Worker", bad+": "+werr.Error())
			} else {
				sb := res.Sandbox
				lvl := sb.Level
				switch lvl {
				case safety.LevelFull:
					lvl = st.Green(lvl)
				case safety.LevelPartial:
					lvl = st.Yellow(lvl)
				default:
					lvl = st.Red(lvl)
				}
				row("Confinement", lvl)
				row("no_new_privs", yesno(sb.NoNewPrivs))
				row("Landlock", fmt.Sprintf("%s (kernel ABI %d)", yesno(sb.Landlock), sb.LandlockABI))
				row("Landlock network", yesno(sb.LandlockNet))
				row("seccomp-bpf", yesno(sb.Seccomp))
				row("Memory limit", yesno(sb.MemoryLimit))
				if sb.Detail != "" {
					row("Notes", sb.Detail)
				}
				var t engine.SelfTestResult
				if json.Unmarshal(res.Raw, &t) == nil {
					row("Read /etc/passwd", t.ReadEtcPasswd)
					row("Write temp file", t.WriteTemp)
					row("Open network", t.NetworkDial)
				}
				if sb.Level != safety.LevelFull {
					fmt.Fprintln(out, "  "+st.Yellow("Confinement is not full on this system. Use require_sandbox: true to refuse to analyse without it."))
				}
			}

			fmt.Fprintln(out, "\n"+st.Bold("Optional tools (detected only; no adapters exist in this build)"))
			for _, t := range optionalTools {
				p, err := exec.LookPath(t.bin)
				if err != nil {
					row(t.name, st.Dim("not found — "+t.role))
					continue
				}
				row(t.name, p+" "+st.Dim(toolVersion(p)))
			}
			fmt.Fprintln(out, "\n"+st.Dim("Missing optional tools never stop UNPACKR from working."))
			return nil
		},
	}
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// toolVersion asks a tool for its version with a short timeout and a scrubbed
// environment. Output is sanitised and truncated.
func toolVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	b, _ := cmd.CombinedOutput()
	line := strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	if len(line) > 80 {
		line = line[:80]
	}
	return terminal.Sanitize(line)
}
