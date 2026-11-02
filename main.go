package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CPU struct{ User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64 }
type Pressure struct {
	Avg10, Avg60, Avg300 float64
	Total                uint64
}
type Task struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	State       string  `json:"state"`
	Threads     int     `json:"threads"`
	Priority    int64   `json:"priority"`
	Nice        int64   `json:"nice"`
	CPU         uint64  `json:"cpu_ticks"`
	CPUPercent  float64 `json:"cpu_percent"`
	Voluntary   uint64  `json:"voluntary_switches"`
	Involuntary uint64  `json:"involuntary_switches"`
	RunNS       uint64  `json:"runtime_ns,omitempty"`
	WaitNS      uint64  `json:"wait_ns,omitempty"`
	Slices      uint64  `json:"slices,omitempty"`
	Policy      string  `json:"policy,omitempty"`
	CPUAffinity string  `json:"cpu_affinity,omitempty"`
	Migrations  uint64  `json:"migrations,omitempty"`
	Error       string  `json:"error,omitempty"`
}
type Snapshot struct {
	Timestamp         time.Time      `json:"timestamp"`
	Hostname          string         `json:"hostname"`
	Kernel            string         `json:"kernel"`
	CPUs              int            `json:"cpus"`
	Load              [3]float64     `json:"load"`
	Runnable          int            `json:"runnable"`
	TotalTasks        int            `json:"total_tasks"`
	ContextSwitches   uint64         `json:"context_switches"`
	Interrupts        uint64         `json:"interrupts"`
	Forks             uint64         `json:"forks"`
	Blocked           int            `json:"blocked"`
	CPU               map[string]CPU `json:"cpu"`
	CPUUtilization    float64        `json:"cpu_utilization_percent"`
	ContextSwitchRate float64        `json:"context_switches_per_second"`
	ForkRate          float64        `json:"forks_per_second"`
	PressureSome      Pressure       `json:"pressure_some"`
	PressureFull      Pressure       `json:"pressure_full"`
	Tasks             []Task         `json:"tasks"`
	Warnings          []string       `json:"warnings,omitempty"`
}
type Options struct {
	Count      int
	Interval   time.Duration
	Top        int
	Format     string
	Output     string
	Sort       string
	Threshold  float64
	IncludeAll bool
}

func read(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		return ""
	}
	return string(b)
}
func number(s string) uint64 { n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64); return n }
func integer(s string) int   { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }
func kernel() string         { s := read("/proc/sys/kernel/osrelease"); return strings.TrimSpace(s) }
func cpuFields(f []string) CPU {
	var a [8]uint64
	for i := 0; i < 8 && i < len(f); i++ {
		a[i] = number(f[i])
	}
	return CPU{a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]}
}
func cpuTotal(c CPU) uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}
func cpuIdle(c CPU) uint64 { return c.Idle + c.IOWait }
func parseProcStat(s *Snapshot) {
	for _, line := range strings.Split(read("/proc/stat"), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch {
		case strings.HasPrefix(f[0], "cpu"):
			s.CPU[f[0]] = cpuFields(f[1:])
		case f[0] == "ctxt":
			s.ContextSwitches = number(f[1])
		case f[0] == "intr":
			s.Interrupts = number(f[1])
		case f[0] == "processes":
			s.Forks = number(f[1])
		case f[0] == "procs_running":
			s.Runnable = integer(f[1])
		case f[0] == "procs_blocked":
			s.Blocked = integer(f[1])
		}
	}
}
func parseLoad(s *Snapshot) {
	f := strings.Fields(read("/proc/loadavg"))
	for i := 0; i < 3 && i < len(f); i++ {
		s.Load[i], _ = strconv.ParseFloat(f[i], 64)
	}
	if len(f) > 3 {
		parts := strings.Split(f[3], "/")
		if len(parts) == 2 {
			s.TotalTasks = integer(parts[1])
		}
	}
}
func parsePressure(path string) (Pressure, Pressure) {
	var some, full Pressure
	for _, line := range strings.Split(read(path), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		p := &some
		if f[0] == "full" {
			p = &full
		} else if f[0] != "some" {
			continue
		}
		for _, v := range f[1:] {
			a := strings.SplitN(v, "=", 2)
			if len(a) != 2 {
				continue
			}
			switch a[0] {
			case "avg10":
				p.Avg10, _ = strconv.ParseFloat(a[1], 64)
			case "avg60":
				p.Avg60, _ = strconv.ParseFloat(a[1], 64)
			case "avg300":
				p.Avg300, _ = strconv.ParseFloat(a[1], 64)
			case "total":
				p.Total = number(a[1])
			}
		}
	}
	return some, full
}
func statusFields(pid int) (map[string]string, error) {
	f, e := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		a := strings.SplitN(sc.Text(), ":", 2)
		if len(a) == 2 {
			m[a[0]] = strings.TrimSpace(a[1])
		}
	}
	return m, sc.Err()
}
func statFields(pid int) ([]string, error) {
	s := read(fmt.Sprintf("/proc/%d/stat", pid))
	if s == "" {
		return nil, errors.New("stat unavailable")
	}
	i := strings.LastIndex(s, ")")
	if i < 0 {
		return nil, errors.New("malformed stat")
	}
	return strings.Fields(strings.TrimSpace(s[i+1:])), nil
}
func schedFields(pid int) (uint64, uint64, uint64, uint64, string) {
	var run, wait, slices, migrations uint64
	policy := ""
	for _, line := range strings.Split(read(fmt.Sprintf("/proc/%d/sched", pid)), "\n") {
		a := strings.SplitN(line, ":", 2)
		if len(a) != 2 {
			continue
		}
		k := strings.TrimSpace(a[0])
		v := strings.Fields(a[1])
		if len(v) == 0 {
			continue
		}
		switch k {
		case "se.sum_exec_runtime":
			f, _ := strconv.ParseFloat(v[0], 64)
			if f > 0 {
				run = uint64(f * 1e6)
			}
		case "se.statistics.wait_sum":
			f, _ := strconv.ParseFloat(v[0], 64)
			if f > 0 {
				wait = uint64(f * 1e6)
			}
		case "nr_switches":
			slices = number(v[0])
		case "se.nr_migrations":
			migrations = number(v[0])
		case "policy":
			policy = v[0]
		}
	}
	return run, wait, slices, migrations, policy
}
func task(pid int) (Task, error) {
	t := Task{PID: pid}
	f, e := statFields(pid)
	if e != nil {
		return t, e
	}
	if len(f) < 22 {
		return t, errors.New("short stat")
	}
	t.State = f[0]
	t.CPU = number(f[11]) + number(f[12])
	t.Priority, _ = strconv.ParseInt(f[15], 10, 64)
	t.Nice, _ = strconv.ParseInt(f[16], 10, 64)
	t.Threads = integer(f[17])
	m, e := statusFields(pid)
	if e == nil {
		t.Name = m["Name"]
		t.CPUAffinity = m["Cpus_allowed_list"]
		t.Voluntary = number(m["voluntary_ctxt_switches"])
		t.Involuntary = number(m["nonvoluntary_ctxt_switches"])
	}
	if t.Name == "" {
		t.Name = strings.TrimSpace(read(fmt.Sprintf("/proc/%d/comm", pid)))
	}
	t.RunNS, t.WaitNS, t.Slices, t.Migrations, t.Policy = schedFields(pid)
	return t, nil
}
func snapshot() Snapshot {
	h, _ := os.Hostname()
	s := Snapshot{Timestamp: time.Now(), Hostname: h, Kernel: kernel(), CPUs: runtime.NumCPU(), CPU: map[string]CPU{}, Tasks: []Task{}}
	parseProcStat(&s)
	parseLoad(&s)
	s.PressureSome, s.PressureFull = parsePressure("/proc/pressure/cpu")
	entries, e := os.ReadDir("/proc")
	if e != nil {
		s.Warnings = append(s.Warnings, e.Error())
		return s
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		t, e := task(pid)
		if e == nil {
			s.Tasks = append(s.Tasks, t)
		}
	}
	return s
}
func delta(a, b uint64) uint64 {
	if b < a {
		return 0
	}
	return b - a
}
func enrich(now *Snapshot, prev *Snapshot, elapsed float64) {
	if prev == nil || elapsed <= 0 {
		return
	}
	a, ok1 := prev.CPU["cpu"]
	b, ok2 := now.CPU["cpu"]
	if ok1 && ok2 {
		total := delta(cpuTotal(a), cpuTotal(b))
		idle := delta(cpuIdle(a), cpuIdle(b))
		if total > 0 {
			now.CPUUtilization = 100 * float64(total-idle) / float64(total)
		}
	}
	now.ContextSwitchRate = float64(delta(prev.ContextSwitches, now.ContextSwitches)) / elapsed
	now.ForkRate = float64(delta(prev.Forks, now.Forks)) / elapsed
	old := map[int]Task{}
	for _, t := range prev.Tasks {
		old[t.PID] = t
	}
	for i := range now.Tasks {
		t := &now.Tasks[i]
		if p, ok := old[t.PID]; ok {
			ticks := delta(p.CPU, t.CPU)
			t.CPUPercent = 100 * float64(ticks) / float64(runtime.NumCPU()) / 100 / elapsed * float64(runtime.NumCPU())
		}
	}
}
func sortTasks(ts []Task, key string) {
	sort.Slice(ts, func(i, j int) bool {
		a, b := ts[i], ts[j]
		switch key {
		case "wait":
			return a.WaitNS > b.WaitNS
		case "switches":
			return a.Voluntary+a.Involuntary > b.Voluntary+b.Involuntary
		case "migrations":
			return a.Migrations > b.Migrations
		case "pid":
			return a.PID < b.PID
		default:
			return a.CPUPercent > b.CPUPercent
		}
	})
}
func evaluate(s *Snapshot, threshold float64) {
	if s.PressureSome.Avg10 >= threshold {
		s.Warnings = append(s.Warnings, fmt.Sprintf("CPU PSI some avg10 %.2f exceeds %.2f", s.PressureSome.Avg10, threshold))
	}
	if s.Runnable > s.CPUs*2 {
		s.Warnings = append(s.Warnings, fmt.Sprintf("runnable tasks %d exceed twice logical CPUs %d", s.Runnable, s.CPUs))
	}
	if s.Load[0] > float64(s.CPUs)*1.5 {
		s.Warnings = append(s.Warnings, "one-minute load exceeds 1.5 times logical CPU count")
	}
}
func renderText(w io.Writer, s Snapshot, top int) {
	fmt.Fprintf(w, "\nSCHEDULER FORENSICS  %s  %s  %s\n", s.Timestamp.Format(time.RFC3339), s.Hostname, s.Kernel)
	fmt.Fprintf(w, "CPUs=%d load=%.2f/%.2f/%.2f runnable=%d blocked=%d tasks=%d\n", s.CPUs, s.Load[0], s.Load[1], s.Load[2], s.Runnable, s.Blocked, len(s.Tasks))
	fmt.Fprintf(w, "CPU utilization=%.2f%% context-switches/s=%.2f forks/s=%.2f\n", s.CPUUtilization, s.ContextSwitchRate, s.ForkRate)
	fmt.Fprintf(w, "CPU PSI some avg10=%.2f avg60=%.2f avg300=%.2f total=%d us\n", s.PressureSome.Avg10, s.PressureSome.Avg60, s.PressureSome.Avg300, s.PressureSome.Total)
	fmt.Fprintf(w, "CPU PSI full avg10=%.2f avg60=%.2f avg300=%.2f total=%d us\n", s.PressureFull.Avg10, s.PressureFull.Avg60, s.PressureFull.Avg300, s.PressureFull.Total)
	for _, v := range s.Warnings {
		fmt.Fprintln(w, "WARNING:", v)
	}
	fmt.Fprintln(w, "PID      CPU%     NICE  PRI   THREADS  VOL-CS       INV-CS       MIGRATIONS  NAME")
	if top <= 0 || top > len(s.Tasks) {
		top = len(s.Tasks)
	}
	for _, t := range s.Tasks[:top] {
		fmt.Fprintf(w, "%-8d %-8.2f %-5d %-5d %-8d %-12d %-12d %-11d %s\n", t.PID, t.CPUPercent, t.Nice, t.Priority, t.Threads, t.Voluntary, t.Involuntary, t.Migrations, t.Name)
	}
}
func renderCSV(w io.Writer, s Snapshot, top int) error {
	c := csv.NewWriter(w)
	if err := c.Write([]string{"timestamp", "pid", "name", "state", "cpu_percent", "nice", "priority", "threads", "voluntary_switches", "involuntary_switches", "migrations", "runtime_ns", "wait_ns"}); err != nil {
		return err
	}
	if top <= 0 || top > len(s.Tasks) {
		top = len(s.Tasks)
	}
	for _, t := range s.Tasks[:top] {
		row := []string{s.Timestamp.Format(time.RFC3339), strconv.Itoa(t.PID), t.Name, t.State, fmt.Sprintf("%.3f", t.CPUPercent), strconv.FormatInt(t.Nice, 10), strconv.FormatInt(t.Priority, 10), strconv.Itoa(t.Threads), strconv.FormatUint(t.Voluntary, 10), strconv.FormatUint(t.Involuntary, 10), strconv.FormatUint(t.Migrations, 10), strconv.FormatUint(t.RunNS, 10), strconv.FormatUint(t.WaitNS, 10)}
		if e := c.Write(row); e != nil {
			return e
		}
	}
	c.Flush()
	return c.Error()
}
func run(o Options) error {
	var w io.Writer = os.Stdout
	var f *os.File
	if o.Output != "" {
		var e error
		f, e = os.Create(filepath.Clean(o.Output))
		if e != nil {
			return e
		}
		defer f.Close()
		w = f
	}
	var prev *Snapshot
	var encoder *json.Encoder
	if o.Format == "json" {
		encoder = json.NewEncoder(w)
		encoder.SetIndent("", "  ")
	}
	for i := 0; i < o.Count; i++ {
		if i > 0 {
			time.Sleep(o.Interval)
		}
		s := snapshot()
		if prev != nil {
			enrich(&s, prev, s.Timestamp.Sub(prev.Timestamp).Seconds())
		}
		evaluate(&s, o.Threshold)
		sortTasks(s.Tasks, o.Sort)
		switch o.Format {
		case "json":
			if e := encoder.Encode(s); e != nil {
				return e
			}
		case "csv":
			if e := renderCSV(w, s, o.Top); e != nil {
				return e
			}
		default:
			renderText(w, s, o.Top)
		}
		prev = &s
	}
	return nil
}
func main() {
	o := Options{}
	flag.IntVar(&o.Count, "count", 1, "number of snapshots")
	flag.DurationVar(&o.Interval, "interval", 2*time.Second, "time between snapshots")
	flag.IntVar(&o.Top, "top", 20, "number of tasks to display, 0 for all")
	flag.StringVar(&o.Format, "format", "text", "text, json, or csv")
	flag.StringVar(&o.Output, "output", "", "output file")
	flag.StringVar(&o.Sort, "sort", "cpu", "cpu, wait, switches, migrations, pid")
	flag.Float64Var(&o.Threshold, "psi-threshold", 20, "CPU PSI some avg10 warning threshold")
	flag.Parse()
	if o.Count < 1 || o.Interval <= 0 || o.Top < 0 {
		fmt.Fprintln(os.Stderr, "invalid count, interval, or top")
		os.Exit(2)
	}
	if o.Format != "text" && o.Format != "json" && o.Format != "csv" {
		fmt.Fprintln(os.Stderr, "invalid format")
		os.Exit(2)
	}
	if e := run(o); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
