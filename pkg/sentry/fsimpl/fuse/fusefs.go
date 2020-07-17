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

// Package fuse implements fusefs.
package fuse

import (
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Name is the default filesystem name.
const Name = "fuse"

// FilesystemType implements vfs.FilesystemType.
type FilesystemType struct{}

type filesystemOptions struct {
	// userID specifies the numeric uid of the mount owner.
	// This option should not be specified by the filesystem owner.
	// It is set by libfuse (or, if libfuse is not used, must be set
	// by the filesystem itself). For more information, see man page
	// for fuse(8)
	userID uint32

	// groupID specifies the numeric gid of the mount owner.
	// This option should not be specified by the filesystem owner.
	// It is set by libfuse (or, if libfuse is not used, must be set
	// by the filesystem itself). For more information, see man page
	// for fuse(8)
	groupID uint32

	// rootMode specifies the the file mode of the filesystem's root.
	rootMode linux.FileMode

	// maxActiveRequests specifies the maximum number of active requests that can
	// exist at any time. Any further requests will block when trying to
	// Call the server.
	maxActiveRequests uint64
}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem
	devMinor uint32

	// conn is used for communication between the FUSE server
	// daemon and the sentry fusefs.
	conn *Connection

	// opts is the options the fusefs is initialized with.
	opts *filesystemOptions
}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}

	var fsopts filesystemOptions
	mopts := vfs.GenericParseMountOptions(opts.Data)
	deviceDescriptorStr, ok := mopts["fd"]
	if !ok {
		log.Warningf("%s.GetFilesystem: communication file descriptor N (obtained by opening /dev/fuse) must be specified as 'fd=N'", fsType.Name())
		return nil, nil, syserror.EINVAL
	}
	delete(mopts, "fd")

	deviceDescriptor, err := strconv.ParseInt(deviceDescriptorStr, 10 /* base */, 32 /* bitSize */)
	if err != nil {
		return nil, nil, err
	}

	kernelTask := kernel.TaskFromContext(ctx)
	if kernelTask == nil {
		log.Warningf("%s.GetFilesystem: couldn't get kernel task from context", fsType.Name())
		return nil, nil, syserror.EINVAL
	}
	fuseFd := kernelTask.GetFileVFS2(int32(deviceDescriptor))

	// Parse and set all the other supported FUSE mount options.
	// TODO(gVisor.dev/issue/3229): Expand the supported mount options.
	if userIDStr, ok := mopts["user_id"]; ok {
		delete(mopts, "user_id")
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid user_id: user_id=%s", fsType.Name(), userIDStr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.userID = uint32(userID)
	}

	if groupIDStr, ok := mopts["group_id"]; ok {
		delete(mopts, "group_id")
		groupID, err := strconv.ParseUint(groupIDStr, 10, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid group_id: group_id=%s", fsType.Name(), groupIDStr)
			return nil, nil, syserror.EINVAL
		}
		fsopts.groupID = uint32(groupID)
	}

	rootMode := linux.FileMode(0777)
	modeStr, ok := mopts["rootmode"]
	if ok {
		delete(mopts, "rootmode")
		mode, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			log.Warningf("%s.GetFilesystem: invalid mode: %q", fsType.Name(), modeStr)
			return nil, nil, syserror.EINVAL
		}
		rootMode = linux.FileMode(mode)
	}
	fsopts.rootMode = rootMode

	// Set the maxInFlightRequests option.
	fsopts.maxActiveRequests = MaxActiveRequestsDefault

	// Check for unparsed options.
	if len(mopts) != 0 {
		log.Warningf("%s.GetFilesystem: unknown options: %v", fsType.Name(), mopts)
		return nil, nil, syserror.EINVAL
	}

	// Create a new FUSE filesystem.
	fs, err := NewFUSEFilesystem(ctx, devMinor, &fsopts, fuseFd)
	if err != nil {
		log.Warningf("%s.NewFUSEFilesystem: failed with error: %v", fsType.Name(), err)
		return nil, nil, err
	}

	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)

	// Send a FUSE_INIT request to the FUSE daemon server before returning.
	// This call is not blocking.
	if err := fs.InitSend(creds, uint32(kernelTask.ThreadID())); err != nil {
		log.Warningf("%s.InitSend: failed with error: %v", fsType.Name(), err)
		return nil, nil, err
	}

	// root is the fusefs root directory.
	defaultFusefsDirMode := linux.FileMode(0755)
	root := fs.newRootInode(creds, defaultFusefsDirMode)

	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// NewFUSEFilesystem creates a new FUSE filesystem.
func NewFUSEFilesystem(ctx context.Context, devMinor uint32, opts *filesystemOptions, device *vfs.FileDescription) (*filesystem, error) {
	fs := &filesystem{
		devMinor: devMinor,
		opts:     opts,
	}

	conn, err := NewFUSEConnection(ctx, device, opts.maxActiveRequests)
	if err != nil {
		log.Warningf("fuse.NewFUSEFilesystem: Newi.fs.conn failed with error: %v", err)
		return nil, syserror.EINVAL
	}

	fs.conn = conn
	fuseFD := device.Impl().(*DeviceFD)
	fuseFD.fs = fs

	return fs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release()
}

// Inode implements kernfs.Inode.
type Inode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoDynamicLookup
	kernfs.InodeNotSymlink
	kernfs.InodeDirectoryNoNewChildren
	kernfs.OrderedChildren

	NodeID uint64
	dentry kernfs.Dentry
	locks  vfs.FileLocks

	// the owning filesystem. fs is immutable.
	fs *filesystem

	// size indicate the size of the file.
	size uint64

	// access, change and modification time of the file
	atime ktime.Time
	ctime ktime.Time
	mtime ktime.Time

	// attributeVersion is the version of last change in attribute.
	attributeVersion uint64

	// attributeTime represents the time until the file attributes are valid.
	attributeTime uint64

	// version is the version of this inode.
	version uint64

	// imutex serializes changes to a inode.
	imutex sync.Mutex
}

func (fs *filesystem) newRootInode(creds *auth.Credentials, mode linux.FileMode) *kernfs.Dentry {
	i := &Inode{fs: fs}
	i.InodeAttrs.Init(creds, linux.UNNAMED_MAJOR, fs.devMinor, 1, linux.ModeDirectory|0755)
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.dentry.Init(i)
	i.NodeID = 1

	return &i.dentry
}

func (fs *filesystem) newInode(nodeID uint64, generation uint64, attr linux.FUSEAttr) *kernfs.Dentry {
	i := &Inode{fs: fs, NodeID: nodeID}
	creds := auth.Credentials{EffectiveKGID: auth.KGID(attr.UID), EffectiveKUID: auth.KUID(attr.UID)}
	i.InodeAttrs.Init(&creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.FileMode(attr.Mode))
	i.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	i.dentry.Init(i)

	return &i.dentry
}

// Open implements kernfs.Inode.Open.
func (i *Inode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_LARGEFILE == 0 && i.size > linux.MAX_NON_LFS {
		return nil, syserror.EOVERFLOW
	}

	if opts.Flags&linux.O_TRUNC != 0 && i.fs.conn.AtomicOTrunc && i.fs.conn.WritebackCache {
		i.imutex.Lock()
		defer i.imutex.Unlock()
	}

	var fd *fileDescription
	var fdImpl vfs.FileDescriptionImpl

	if !i.fs.conn.NoOpen || opts.Mode.IsDir() {
		kernelTask := kernel.TaskFromContext(ctx)
		if kernelTask == nil {
			log.Warningf("fusefs.DeviceFD.Read: couldn't get kernel task from context")
			return nil, syserror.EINVAL
		}

		// Build the request.
		var opcode linux.FUSEOpcode
		if opts.Mode.IsDir() {
			opcode = linux.FUSE_OPENDIR
		} else {
			opcode = linux.FUSE_OPEN
		}

		in := linux.FUSEOpenIn{Flags: opts.Flags & ^uint32(linux.O_CREAT|linux.O_EXCL|linux.O_NOCTTY)}
		if !i.fs.conn.AtomicOTrunc {
			in.Flags &= ^uint32(linux.O_TRUNC)
		}

		req, err := i.fs.conn.NewRequest(auth.CredentialsFromContext(ctx), uint32(kernelTask.ThreadID()), i.NodeID, opcode, &in)
		if err != nil {
			return nil, err
		}

		// Send and recv the request.
		res, err := i.fs.conn.Call(kernelTask, req)
		if err == syserror.ENOSYS && !opts.Mode.IsDir() {
			i.fs.conn.NoOpen = true
		} else if err != nil {
			return nil, err
		}

		if err := res.Error(); err != nil {
			return nil, err
		}

		out := linux.FUSEOpenOut{}
		if err := res.UnmarshalPayload(&out); err != nil {
			return nil, err
		}

		// Process the reply.
		if opts.Mode.IsDir() {
			fd = &fileDescription{}
			fdImpl = fd

			fd.OpenFlag = out.OpenFlag
			fd.OpenFlag &= ^uint32(linux.FOPEN_DIRECT_IO)
		} else {
			regularFd := &regularFileFD{}
			fd = &(regularFd.fileDescription)
			fdImpl = regularFd

			fd.OpenFlag = out.OpenFlag
		}

		fd.Fh = out.Fh
	} else {
		fd := &fileDescription{}
		fdImpl = fd
	}

	// TODO(gvisor.dev/issue/3234): invalidate mmap after mmap had been implemented for FUSE Inode
	fd.directIO = fd.OpenFlag&linux.FOPEN_DIRECT_IO != 0
	fdOptions := &vfs.FileDescriptionOptions{}
	if fd.OpenFlag&linux.FOPEN_NONSEEKABLE != 0 {
		fdOptions.DenyPRead = true
		fdOptions.DenyPWrite = true
		fd.Nonseekable = true
	}
	if i.fs.conn.AtomicOTrunc && opts.Flags&linux.O_TRUNC != 0 {
		i.fs.conn.Lock.Lock()
		i.fs.conn.AttributeVersion++
		i.attributeVersion = i.fs.conn.AttributeVersion
		i.size = 0
		i.fs.conn.Lock.Unlock()
		i.attributeTime = 0
		if i.fs.conn.WritebackCache {
			i.ctime = ktime.NowFromContext(ctx)
			i.mtime = ktime.NowFromContext(ctx)
			i.version++
		}
	}

	if err := fd.vfsfd.Init(fdImpl, opts.Flags, rp.Mount(), vfsd, fdOptions); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// fileDescription implements vfs.FileDescriptionImpl for fuse.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// the file handle used in userspace.
	Fh uint64

	// Nonseekable is indicate cannot perform seek on a file.
	Nonseekable bool

	// directIO suggest fuse to use direct io operation.
	directIO bool

	// OpenFlag is the flag returned by open.
	OpenFlag uint32
}

func (fd *fileDescription) inode() *Inode {
	return fd.vfsfd.Dentry().Impl().(*kernfs.Dentry).Inode().(*Inode)
}

func (fd *fileDescription) statusFlags() uint32 {
	return fd.vfsfd.StatusFlags()
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fileDescription) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, nil
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *fileDescription) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, nil
}

// maskedFUSEAttr masks attributes from linux.FUSEAttr to linux.Statx. The
// opts.Sync attribute is ignored since the synchronization is handled by the
// FUSE server.
func maskedFUSEAttr(attr linux.FUSEAttr, mask uint32) linux.Statx {
	var stat linux.Statx
	stat.Blksize = attr.BlkSize

	if mask&linux.STATX_MODE != 0 {
		stat.Mode = uint16(attr.Mode)
	}
	if mask&linux.STATX_NLINK != 0 {
		stat.Nlink = attr.Nlink
	}
	if mask&linux.STATX_UID != 0 {
		stat.UID = attr.UID
	}
	if mask&linux.STATX_GID != 0 {
		stat.GID = attr.GID
	}
	if mask&linux.STATX_ATIME != 0 {
		stat.Atime = linux.StatxTimestamp{
			Sec:  int64(attr.Atime),
			Nsec: attr.AtimeNsec,
		}
	}
	if mask&linux.STATX_MTIME != 0 {
		stat.Mtime = linux.StatxTimestamp{
			Sec:  int64(attr.Mtime),
			Nsec: attr.MtimeNsec,
		}
	}
	if mask&linux.STATX_CTIME != 0 {
		stat.Ctime = linux.StatxTimestamp{
			Sec:  int64(attr.Ctime),
			Nsec: attr.CtimeNsec,
		}
	}
	if mask&linux.STATX_INO != 0 {
		stat.Ino = attr.Ino
	}
	if mask&linux.STATX_SIZE != 0 {
		stat.Size = attr.Size
	}
	if mask&linux.STATX_BLOCKS != 0 {
		stat.Blocks = attr.Blocks
	}
	return stat
}

func (i *Inode) Lookup(ctx context.Context, name string) (*vfs.Dentry, error) {
	fusefs := i.fs
	task, creds := kernel.TaskFromContext(ctx), auth.CredentialsFromContext(ctx)

	in := linux.FUSELookupIn{Name: name}
	req, err := fusefs.conn.NewRequest(creds, uint32(task.ThreadID()), i.NodeID, linux.FUSE_LOOKUP, &in)
	if err != nil {
		return nil, err
	}

	res, err := fusefs.conn.Call(task, req)
	if err != nil {
		return nil, err
	}
	if err := res.Error(); err != nil {
		return nil, err
	}

	var out linux.FUSEEntryOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return nil, err
	}

	child := fusefs.newInode(out.NodeID, out.Generation, out.Attr)
	i.dentry.InsertChildLocked(name, child)
	return child.VFSDentry(), nil
}

// IterDirents implements Inode.IterDirents.
func (Inode) IterDirents(ctx context.Context, callback vfs.IterDirentsCallback, offset, relOffset int64) (int64, error) {
	return offset, nil
}

// Valid implements Inode.Valid.
func (Inode) Valid(ctx context.Context) bool {
	return true
}

// Stat implements kernfs.Inode.Stat.
func (i *Inode) Stat(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	conn := fs.Impl().(*filesystem).conn
	task, creds := kernel.TaskFromContext(ctx), auth.CredentialsFromContext(ctx)
	if task == nil {
		log.Warningf("couldn't get kernel task from context")
		return linux.Statx{}, syserror.EINVAL
	}

	var in linux.FUSEGetAttrIn
	// We don't set any attribute in the request, because in VFS2 fstat(2) will
	// finally be translated into vfs.FilesystemImpl.StatAt() (see
	// pkg/sentry/syscalls/linux/vfs2/stat.go), resulting in the same flow
	// as stat(2). Thus GetAttrFlags and Fh variable will never be used in VFS2.
	req, err := conn.NewRequest(creds, uint32(task.ThreadID()), i.NodeID, linux.FUSE_GETATTR, &in)
	if err != nil {
		return linux.Statx{}, nil
	}

	res, err := conn.Call(task, req)
	if err != nil {
		return linux.Statx{}, err
	}
	if err := res.Error(); err != nil {
		return linux.Statx{}, err
	}

	var out linux.FUSEGetAttrOut
	if err := res.UnmarshalPayload(&out); err != nil {
		return linux.Statx{}, err
	}

	return maskedFUSEAttr(out.Attr, opts.Mask), nil
}
