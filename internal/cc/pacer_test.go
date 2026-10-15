package cc

import (
	"testing"
	"time"
)

func TestInitialWindowAndPace(t *testing.T) {
	p := New(1000)
	if p.State() != Startup || p.Gain() != startupGain {
		t.Fatalf("state %s gain %v", p.State(), p.Gain())
	}
	if p.Cap() != 10*1000 {
		t.Fatal(p.Cap())
	}
	if !p.CanSend(0, 1000) {
		t.Fatal("first send")
	}
	p.OnSend(1000, 0)
	if p.CanSend(0, 1000) {
		t.Fatal("second send was not paced")
	}
	w := p.WakeAt(0)
	if w <= 0 {
		t.Fatalf("wake %s", w)
	}
	if !p.CanSend(w, 1000) {
		t.Fatal("not ready at WakeAt")
	}
}

func TestLossCutsOncePerRound(t *testing.T) {
	p := New(100)
	p.OnSend(1000, 0)
	p.OnLoss(0)
	if p.State() != Drain || p.Gain() != drainGain {
		t.Fatalf("state %s gain %v", p.State(), p.Gain())
	}
	cap := p.Cap()
	if cap != 850 {
		t.Fatalf("cap %d", cap)
	}
	p.OnLoss(0)
	if p.Cap() != cap {
		t.Fatalf("cut twice: %d then %d", cap, p.Cap())
	}
}

func TestStartupExitsWhenBandwidthStalls(t *testing.T) {
	p := New(100)
	p.OnSend(5000, 0)
	p.OnRTT(time.Millisecond, 0)
	var del uint64
	for i := 1; i <= 4; i++ {
		del += 1000
		p.Sample(del, time.Duration(i)*time.Millisecond)
	}
	if p.State() != Drain {
		t.Fatalf("state %s", p.State())
	}
}

func TestProbeBWCycle(t *testing.T) {
	p := New(100)
	p.OnRTT(time.Millisecond, 0)
	p.OnLoss(0)
	if !p.CanSend(0, 100) {
		t.Fatal("send")
	}
	if p.State() != ProbeBW || p.Gain() != 1.25 {
		t.Fatalf("enter %s %v", p.State(), p.Gain())
	}
	p.CanSend(time.Millisecond, 100)
	if p.Gain() != 0.75 {
		t.Fatalf("second phase %v", p.Gain())
	}
	p.CanSend(2*time.Millisecond, 100)
	if p.Gain() != 1 {
		t.Fatalf("third phase %v", p.Gain())
	}
}

func TestProbeRTT(t *testing.T) {
	p := New(100)
	p.OnRTT(time.Millisecond, 0)
	p.CanSend(10*time.Second, 100)
	if p.State() != ProbeRTT || p.Cap() != 400 {
		t.Fatalf("state %s cap %d", p.State(), p.Cap())
	}
	p.CanSend(10*time.Second+200*time.Millisecond, 100)
	if p.State() != ProbeBW {
		t.Fatalf("left probe_rtt into %s", p.State())
	}
}

func TestECNIsLoss(t *testing.T) {
	p := New(100)
	p.OnSend(500, 0)
	p.OnECN(0, 0)
	if p.State() != Startup {
		t.Fatal(p.State())
	}
	p.OnECN(3, 0)
	if p.State() != Drain {
		t.Fatal(p.State())
	}
}

func TestAppLimitedSkipsBandwidth(t *testing.T) {
	p := New(100)
	p.OnRTT(time.Millisecond, 0)
	p.Sample(1000, time.Millisecond)
	bw := p.bw
	p.SetAppLimited(true)
	p.Sample(1000, 2*time.Millisecond)
	if p.bw != bw {
		t.Fatalf("bw changed while app-limited: %v -> %v", bw, p.bw)
	}
}
