// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_splitseg_mss_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

// TestTCPSplitSegMSS lets the dut try to send segments larger than MSS.
// It tests if the transmitted segments are capped at MSS and are split.
func TestTCPSplitSegMSS(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFD, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFD)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	const mss = uint32(536)
	options := make([]byte, header.TCPOptionMSSLength)
	header.EncodeMSSOption(mss, options)
	conn.Handshake(options...)

	acceptFD, _ := dut.Accept(listenFD)
	defer dut.Close(acceptFD)

	// Let the dut send a segment larger than MSS.
	largeData := make([]byte, mss+1)

	dut.Send(acceptFD, largeData, 0)
	expectedPayload := tb.Payload{Bytes: largeData[:mss]}
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected payload: %s", err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	expectedPayload = tb.Payload{Bytes: largeData[mss:]}
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected payload: %s", err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})

	// Ensure that no segment is transmitted beyond MSS.
	dut.Send(acceptFD, largeData, 0)
	unexpectedPayload := tb.Payload{Bytes: largeData}
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, &unexpectedPayload, 3*time.Second); err == nil {
		t.Fatalf("Unexpected payload")
	}
}
