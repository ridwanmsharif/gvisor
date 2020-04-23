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

package reordering_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

func TestReorderingWindow(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(listenFd)
	conn := tb.NewTCPIPv4(t, tb.TCP{DstPort: &remotePort}, tb.TCP{SrcPort: &remotePort})
	defer conn.Close()

	// Handshake with SACK enabled.
	sackPerm := make([]byte, 40)
	spOff := 0
	spOff += header.EncodeNOP(sackPerm[spOff:])
	spOff += header.EncodeNOP(sackPerm[spOff:])
	spOff += header.EncodeSACKPermittedOption(sackPerm[spOff:])
	conn.HandshakeWithOptions(sackPerm[:spOff])

	acceptFd, _ := dut.Accept(listenFd)
	defer dut.Close(acceptFd)

	mss := dut.GetSockOptInt(acceptFd, unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	payload := make([]byte, mss)

	seqNum1 := *conn.RemoteSeqNum()
	const numPkts = 10
	// Send some packets, checking that we receive each.
	for i, sn := 0, seqNum1; i < numPkts; i++ {
		dut.Send(acceptFd, payload, 0)

		gotOne, err := conn.Expect(tb.TCP{SeqNum: tb.Uint32(uint32(sn))}, time.Second)
		sn.UpdateForward(seqnum.Size(len(payload)))
		if err != nil {
			t.Errorf("Expect #%d: %s", i+1, err)
			continue
		}
		if gotOne == nil {
			t.Errorf("#%d: expected a packet within a second but got none", i+1)
		}
	}

	seqNum2 := *conn.RemoteSeqNum()

	// SACK packets #2-4.
	sackBlock := make([]byte, 40)
	sbOff := 0
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeNOP(sackBlock[sbOff:])
	sbOff += header.EncodeSACKBlocks([]header.SACKBlock{{
		seqNum1.Add(seqnum.Size(len(payload))),
		seqNum1.Add(seqnum.Size(4 * len(payload))),
	}}, sackBlock[sbOff:])
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), AckNum: tb.Uint32(uint32(seqNum1)), Options: sackBlock[:sbOff]})

	// ACK first packet.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), AckNum: tb.Uint32(uint32(seqNum1) + uint32(len(payload)))})

	// Check for retransmit.
	gotOne, err := conn.Expect(tb.TCP{SeqNum: tb.Uint32(uint32(seqNum1))}, time.Second)
	if err != nil {
		t.Fatal("Expect for retransmit:", err)
	}
	if gotOne == nil {
		t.Fatal("expected a retransmitted packet within a second but got none")
	}

	// ACK all sent packets.
	conn.Send(tb.TCP{Flags: tb.Uint8(header.TCPFlagAck), AckNum: tb.Uint32(uint32(seqNum2))})

	// Send half of the original window of packets, checking that we
	// received each.
	for i, sn := 0, seqNum2; i < numPkts/2; i++ {
		dut.Send(acceptFd, payload, 0)

		gotOne, err := conn.Expect(tb.TCP{SeqNum: tb.Uint32(uint32(sn))}, time.Second)
		sn.UpdateForward(seqnum.Size(len(payload)))
		if err != nil {
			t.Errorf("Expect #%d: %s", i+1, err)
			continue
		}
		if gotOne == nil {
			t.Errorf("#%d: expected a packet within a second but got none", i+1)
		}
	}

	if tb.DUTType == "netstack" {
		// The window should now be halved, so we should receive any
		// more, even if we send them.
		dut.Send(acceptFd, payload, 0)
		if got, err := conn.Expect(tb.TCP{}, 100*time.Millisecond); got != nil || err == nil {
			t.Fatalf("expected no packets within 100 millisecond, but got one: %s", got)
		}
		return
	}

	// Linux reduces the window by two. Check that we can receive the rest.
	for i, sn := 0, seqNum2.Add(seqnum.Size(numPkts/2*len(payload))); i < numPkts/2-2; i++ {
		dut.Send(acceptFd, payload, 0)

		gotOne, err := conn.Expect(tb.TCP{SeqNum: tb.Uint32(uint32(sn))}, time.Second)
		sn.UpdateForward(seqnum.Size(len(payload)))
		if err != nil {
			t.Errorf("Expect #%d: %s", i+1, err)
			continue
		}
		if gotOne == nil {
			t.Errorf("#%d: expected a packet within a second but got none", i+1)
		}
	}

	// The window should now be full.
	dut.Send(acceptFd, payload, 0)
	if got, err := conn.Expect(tb.TCP{}, 100*time.Millisecond); got != nil || err == nil {
		t.Fatalf("expected no packets within 100 millisecond, but got one: %s", got)
	}
}
