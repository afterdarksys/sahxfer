package udp

// usableRcv is the granted receive buffer as data bytes. Darwin reports
// the size it set.
func usableRcv(n int) int { return n }
