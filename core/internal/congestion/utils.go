package congestion

import (
	"github.com/XLESSGo/XLESS/core/internal/congestion/bbr"
	"github.com/XLESSGo/XLESS/core/internal/congestion/brutal"
	"github.com/XLESSGo/uquic"
)

func UseBBR(conn quic.Connection) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn quic.Connection, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
