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

package fuse

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Read sends a FUSE_READ request, block on it for reply, process the reply and return the payload as a byte slice.
func (fs *filesystem) Read(ctx context.Context, fd *regularFileFD, off uint64, size uint32) ([]byte, uint32, error) {
	req, err := fs.readBuildRequest(ctx, fd, off, size)
	if err != nil {
		return nil, 0, err
	}

	t := kernel.TaskFromContext(ctx)
	if t == nil {
		log.Warningf("fusefs.DeviceFD.Read: couldn't get kernel task from context")
		return nil, 0, syserror.EINVAL
	}

	// TODO(gvisor/dev/issue/3247): is this a good place to add aio support?
	// if fs.conn.AsyncDio {
	// _, err = fs.conn.Call(nil, req)
	// }

	// TODO: fragment the read if too large

	res, err := fs.conn.Call(t, req)
	if err != nil {
		return nil, 0, err
	}
	if err := res.Error(); err != nil {
		return nil, 0, err
	}

	return res.data, uint32(len(res.data)), nil
}

func (fs *filesystem) readBuildRequest(ctx context.Context, fd *regularFileFD, off uint64, size uint32) (*Request, error) {
	in := linux.FUSEReadIn{
		Fh:        fd.Fh,
		Offset:    off,
		Size:      size,
		LockOwner: 0, // TODO(gvisor.dev/issue/3245): file lock
		ReadFlags: 0, // TODO(gvisor.dev/issue/3245): |= linux.FUSE_READ_LOCKOWNER
		Flags:     fd.statusFlags(),
	}

	return fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernel.TaskFromContext(ctx).ThreadID()), fd.inode().NodeID, linux.FUSE_READ, &in)
}
