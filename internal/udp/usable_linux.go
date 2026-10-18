package udp

// usableRcv is the granted receive buffer as data bytes. Linux reports
// twice what it allows for data (it doubles the request for bookkeeping).
func usableRcv(n int) int { return n / 2 }
