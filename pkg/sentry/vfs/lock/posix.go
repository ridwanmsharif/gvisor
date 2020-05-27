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

package lock

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/syserror"
)

type PosixLocker interface {
	LockRange(uid fslock.UniqueID, t fslock.LockType, rng fslock.LockRange, block fslock.Blocker) error
	UnlockRange(uid fslock.UniqueID, rng fslock.LockRange) error
	Offset() uint64
	Size() (uint64, error)
}

func LockPosix(uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker, fd PosixLocker) error {
	size, err := fd.Size()
	if err != nil {
		return err
	}
	builder := RangeBuilder{
		LockStart:  start,
		LockLength: length,
		Whence:     whence,
		FileOffset: fd.Offset(),
		FileSize:   size,
	}
	rng, err := builder.ComputeRange()
	if err != nil {
		return err
	}
	//return fd.LockRange(uid, t, rng, block)
	return fd.LockRange(uid, t, rng, block)
}

func UnlockPosix(uid fslock.UniqueID, start, length uint64, whence int16, fd PosixLocker) error {
	size, err := fd.Size()
	if err != nil {
		return err
	}
	builder := RangeBuilder{
		LockStart:  start,
		LockLength: length,
		Whence:     whence,
		FileOffset: fd.Offset(),
		FileSize:   size,
	}
	rng, err := builder.ComputeRange()
	if err != nil {
		return err
	}
	return fd.UnlockRange(uid, rng)
}

type RangeBuilder struct {
	LockStart  uint64
	LockLength uint64
	Whence     int16
	FileOffset uint64
	FileSize   uint64
}

func (r *RangeBuilder) ComputeRange() (fslock.LockRange, error) {
	var off uint64
	switch r.Whence {
	case linux.SEEK_SET:
		off = 0
	case linux.SEEK_CUR:
		// Note that Linux does not hold any mutexes while retrieving the file offset,
		// see fs/locks.c:flock_to_posix_lock and fs/locks.c:fcntl_setlk.
		off = r.FileOffset
	case linux.SEEK_END:
		off = r.FileSize
	default:
		return fslock.LockRange{}, syserror.EINVAL
	}

	return fslock.ComputeRange(int64(r.LockStart), int64(r.LockLength), int64(off))
}
