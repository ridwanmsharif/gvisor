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

package tcp_cork_mss_test

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

// TestTCPCorkMSS tests for segment coalesce and split as per MSS.
func TestTCPCorkMSS(t *testing.T) {
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

	dut.SetSockOptInt(acceptFD, unix.IPPROTO_TCP, unix.TCP_CORK, 1)

	// Let the dut application send 2 small segments to be held up and coalesced
	// until the application sends a larger segment to fill upto > MSS.
	sampleData := []byte("Sample Data")
	dut.Send(acceptFD, sampleData, 0)
	dut.Send(acceptFD, sampleData, 0)

	expectedData := sampleData
	expectedData = append(expectedData, sampleData...)
	largeData := make([]byte, mss+1)
	expectedData = append(expectedData, largeData...)
	dut.Send(acceptFD, largeData, 0)

	// Expect the segments to be coalesced and sent and capped to MSS.
	expectedPayload := tb.Payload{Bytes: expectedData[:mss]}
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected payload: %s", err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
	// Expect the coalesced segment to be split and transmitted.
	expectedPayload = tb.Payload{Bytes: expectedData[mss:]}
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected payload: %s", err)
	}

	// Check for segments to "not" be held up because of TCP_CORK when
	// the current send window is lesser than MSS.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), WindowSize: tb.Uint16(uint16(2 * len(sampleData)))})
	dut.Send(acceptFD, sampleData, 0)
	dut.Send(acceptFD, sampleData, 0)
	expectedPayload = tb.Payload{Bytes: append(sampleData, sampleData...)}
	if _, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("Expected payload: %s", err)
	}
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck)})
}
