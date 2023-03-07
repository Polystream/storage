//go:build windows
// +build windows

package lockfile

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

// createLockFileForPath returns a *LockFile object, possibly (depending on the platform)
// working inter-process and associated with the specified path.
//
// This function will be called at most once for each path value within a single process.
//
// If ro, the lock is a read-write lock and the returned *LockFile should correspond to the
// “lock for reading” (shared) operation; otherwise, the lock is either an exclusive lock,
// or a read-write lock and *LockFile should correspond to the “lock for writing” (exclusive) operation.
//
// WARNING:
// - The lock may or MAY NOT be inter-process.
// - There may or MAY NOT be an actual object on the filesystem created for the specified path.
// - Even if ro, the lock MAY be exclusive.
func createLockFileForPath(path string, ro bool) (*LockFile, error) {
	// Check if we can open the lock.
	fd, err := openLock(path, ro)
	if err != nil {
		return nil, err
	}
	windows.Close(fd)

	locktype := writeLock
	if ro {
		locktype = readLock
	}
	return &LockFile{
		file: path,
		ro:   ro,

		rwMutex:    &sync.RWMutex{},
		stateMutex: &sync.Mutex{},
		lw:         newLastWrite(), // For compatibility, the first call of .Modified() will always report a change.
		locktype:   locktype,
		locked:     false,
	}, nil
}

// *LockFile represents a file lock where the file is used to cache an
// identifier of the last party that made changes to whatever's being protected
// by the lock.
//
// It MUST NOT be created manually. Use GetLockFile or GetROLockFile instead.
type LockFile struct {
	file string
	ro   bool

	// rwMutex serializes concurrent reader-writer acquisitions in the same process space
	rwMutex *sync.RWMutex
	// stateMutex is used to synchronize concurrent accesses to the state below
	stateMutex *sync.Mutex

	counter  int64
	lw       LastWrite // A global value valid as of the last .Touch() or .Modified()
	locktype lockType

	locked bool
	// The following fields are only modified on transitions between counter == 0 / counter != 0.
	// Thus, they can be safely accessed by users _that currently hold the LockFile_ without locking.
	// In other cases, they need to be protected using stateMutex.
	fd uintptr
}

// LastWrite is an opaque identifier of the last write to some *LockFile.
// It can be used by users of a *LockFile to determine if the lock indicates changes
// since the last check.
// A default-initialized LastWrite never matches any last write, i.e. it always indicates changes.
type LastWrite struct {
	// Never modify fields of a LastWrite object; it has value semantics.
	state []byte // Contents of the lock file.
}

const lastWriterIDSize = 64    // This must be the same as len(stringid.GenerateRandomID)
var lastWriterIDCounter uint64 // Private state for newLastWriterID

type lockType uint32

const (
	readLock  lockType = 0
	writeLock lockType = windows.LOCKFILE_EXCLUSIVE_LOCK
)

const (
	reserved = 0
	allBytes = ^uint32(0)
)

func openLock(path string, ro bool) (fd windows.Handle, err error) {
	flags := windows.O_CLOEXEC | os.O_CREATE
	if ro {
		flags |= os.O_RDONLY
	} else {
		flags |= os.O_RDWR
	}
	fd, err = windows.Open(path, flags, windows.S_IWRITE)
	if err == nil {
		return fd, nil
	}

	// the directory of the lockfile seems to be removed, try to create it
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return fd, fmt.Errorf("creating lock file directory: %w", err)
		}

		return openLock(path, ro)
	}

	return fd, &os.PathError{Op: "open", Path: path, Err: err}
}

func (l *LockFile) lock(lType lockType) {
	switch lType {
	case readLock:
		l.rwMutex.RLock()
	case writeLock:
		l.rwMutex.Lock()
	default:
		panic(fmt.Sprintf("attempted to acquire a file lock of unrecognized type %d", lType))
	}
	l.stateMutex.Lock()
	defer l.stateMutex.Unlock()
	if l.counter == 0 {
		// If we're the first reference on the lock, we need to open the file again.
		fd, err := openLock(l.file, l.ro)
		if err != nil {
			panic(err)
		}
		l.fd = uintptr(fd)

		// Optimization: only use the (expensive) fcntl syscall when
		// the counter is 0.  In this case, we're either the first
		// reader lock or a writer lock.
		ol := new(windows.Overlapped)
		for windows.LockFileEx(windows.Handle(l.fd), uint32(lType), reserved, allBytes, allBytes, ol) != nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	l.locktype = lType
	l.locked = true
	l.counter++
}

func (l *LockFile) Lock() {
	if l.ro {
		panic("can't take write lock on read-only lock file")
	} else {
		l.lock(writeLock)
	}
}

func (l *LockFile) RLock() {
	l.lock(readLock)
}

func (l *LockFile) Unlock() {
	l.stateMutex.Lock()
	defer l.stateMutex.Unlock()
	if !l.locked {
		// Panic when unlocking an unlocked lock.  That's a violation
		// of the lock semantics and will reveal such.
		panic("calling Unlock on unlocked lock")
	}
	l.counter--
	if l.counter < 0 {
		// Panic when the counter is negative.  There is no way we can
		// recover from a corrupted lock and we need to protect the
		// storage from corruption.
		panic(fmt.Sprintf("lock %q has been unlocked too often", l.file))
	}
	if l.counter == 0 {
		// We should only release the lock when the counter is 0 to
		// avoid releasing read-locks too early; a given process may
		// acquire a read lock multiple times.
		l.locked = false
		// Close the file descriptor on the last unlock, releasing the
		// file lock.
		ol := new(windows.Overlapped)
		windows.UnlockFileEx(windows.Handle(l.fd), reserved, allBytes, allBytes, ol)
		windows.Close(windows.Handle(l.fd))
	}
	if l.locktype == readLock {
		l.rwMutex.RUnlock()
	} else {
		l.rwMutex.Unlock()
	}
}

func (l *LockFile) AssertLocked() {
	// DO NOT provide a variant that returns the value of l.locked.
	//
	// If the caller does not hold the lock, l.locked might nevertheless be true because another goroutine does hold it, and
	// we can’t tell the difference.
	//
	// Hence, this “AssertLocked” method, which exists only for sanity checks.
	if !l.locked {
		panic("internal error: lock is not held by the expected owner")
	}
}

func (l *LockFile) AssertLockedForWriting() {
	// DO NOT provide a variant that returns the current lock state.
	//
	// The same caveats as for AssertLocked apply equally.

	l.AssertLocked()
	// Like AssertLocked, don’t even bother with l.stateMutex.
	if l.locktype != writeLock {
		panic("internal error: lock is not held for writing")
	}
}

// newLastWriteFromData returns a LastWrite corresponding to data that came from a previous LastWrite.serialize
func newLastWriteFromData(serialized []byte) LastWrite {
	if serialized == nil {
		panic("newLastWriteFromData with nil data")
	}
	return LastWrite{
		state: serialized,
	}
}

// GetLastWrite() returns a LastWrite value corresponding to current state of the lock.
// This is typically called before (_not after_) loading the state when initializing a consumer
// of the data protected by the lock.
// During the lifetime of the consumer, the consumer should usually call ModifiedSince instead.
//
// The caller must hold the lock (for reading or writing) before this function is called.
func (l *LockFile) GetLastWrite() (LastWrite, error) {
	l.AssertLocked()
	contents := make([]byte, lastWriterIDSize)
	ol := new(windows.Overlapped)
	var n uint32
	err := windows.ReadFile(windows.Handle(l.fd), contents, &n, ol)
	if err != nil && err != windows.ERROR_HANDLE_EOF {
		return LastWrite{}, err
	}
	// It is important to handle the partial read case, because
	// the initial size of the lock file is zero, which is a valid
	// state (no writes yet)
	contents = contents[:n]
	return newLastWriteFromData(contents), nil
}

// newLastWrite returns a new "last write" ID.
// The value must be different on every call, and also differ from values
// generated by other processes.
func newLastWrite() LastWrite {
	// The ID is (PID, time, per-process counter, random)
	// PID + time represents both a unique process across reboots,
	// and a specific time within the process; the per-process counter
	// is an extra safeguard for in-process concurrency.
	// The random part disambiguates across process namespaces
	// (where PID values might collide), serves as a general-purpose
	// extra safety, _and_ is used to pad the output to lastWriterIDSize,
	// because other versions of this code exist and they don't work
	// efficiently if the size of the value changes.
	pid := os.Getpid()
	tm := time.Now().UnixNano()
	counter := atomic.AddUint64(&lastWriterIDCounter, 1)

	res := make([]byte, lastWriterIDSize)
	binary.LittleEndian.PutUint64(res[0:8], uint64(tm))
	binary.LittleEndian.PutUint64(res[8:16], counter)
	binary.LittleEndian.PutUint32(res[16:20], uint32(pid))
	if n, err := cryptorand.Read(res[20:lastWriterIDSize]); err != nil || n != lastWriterIDSize-20 {
		panic(err) // This shouldn't happen
	}

	return LastWrite{
		state: res,
	}
}

// serialize returns bytes to write to the lock file to represent the specified write.
func (lw LastWrite) serialize() []byte {
	if lw.state == nil {
		panic("LastWrite.serialize on an uninitialized object")
	}
	return lw.state
}

// RecordWrite updates the lock with a new LastWrite value, and returns the new value.
//
// If this function fails, the LastWriter value of the lock is indeterminate;
// the caller should keep using the previously-recorded LastWrite value,
// and possibly detecting its own modification as an external one:
//
//	lw, err := state.lock.RecordWrite()
//	if err != nil { /* fail */ }
//	state.lastWrite = lw
//
// The caller must hold the lock for writing.
func (l *LockFile) RecordWrite() (LastWrite, error) {
	l.AssertLockedForWriting()
	lw := newLastWrite()
	lockContents := lw.serialize()
	ol := new(windows.Overlapped)
	var n uint32
	err := windows.WriteFile(windows.Handle(l.fd), lockContents, &n, ol)
	if err != nil {
		return LastWrite{}, err
	}
	if int(n) != len(lockContents) {
		return LastWrite{}, windows.ERROR_DISK_FULL
	}
	return lw, nil
}

// Equals returns true if lw matches other
func (lw LastWrite) equals(other LastWrite) bool {
	if lw.state == nil {
		panic("LastWrite.equals on an uninitialized object")
	}
	if other.state == nil {
		panic("LastWrite.equals with an uninitialized counterparty")
	}
	return bytes.Equal(lw.state, other.state)
}

// ModifiedSince checks if the lock has been changed since a provided LastWrite value,
// and returns the one to record instead.
//
// If ModifiedSince reports no modification, the previous LastWrite value
// is still valid and can continue to be used.
//
// If this function fails, the LastWriter value of the lock is indeterminate;
// the caller should fail and keep using the previously-recorded LastWrite value,
// so that it continues failing until the situation is resolved. Similarly,
// it should only update the recorded LastWrite value after processing the update:
//
//	lw2, modified, err := state.lock.ModifiedSince(state.lastWrite)
//	if err != nil { /* fail */ }
//	state.lastWrite = lw2
//	if modified {
//		if err := reload(); err != nil { /* fail */ }
//		state.lastWrite = lw2
//	}
//
// The caller must hold the lock (for reading or writing).
func (l *LockFile) ModifiedSince(previous LastWrite) (LastWrite, bool, error) {
	l.AssertLocked()
	currentLW, err := l.GetLastWrite()
	if err != nil {
		return LastWrite{}, false, err
	}
	modified := !previous.equals(currentLW)
	return currentLW, modified, nil
}

// Deprecated: Use *LockFile.ModifiedSince.
func (l *LockFile) Modified() (bool, error) {
	l.stateMutex.Lock()
	if !l.locked {
		panic("attempted to check last-writer in lockfile without locking it first")
	}
	defer l.stateMutex.Unlock()
	oldLW := l.lw
	// Note that this is called with stateMutex held; that’s fine because ModifiedSince doesn’t need to lock it.
	currentLW, modified, err := l.ModifiedSince(oldLW)
	if err != nil {
		return true, err
	}
	l.lw = currentLW
	return modified, nil
}

// Deprecated: Use *LockFile.RecordWrite.
func (l *LockFile) Touch() error {
	lw, err := l.RecordWrite()
	if err != nil {
		return err
	}
	l.stateMutex.Lock()
	if !l.locked || (l.locktype != writeLock) {
		panic("attempted to update last-writer in lockfile without the write lock")
	}
	defer l.stateMutex.Unlock()
	l.lw = lw
	return nil
}
func (l *LockFile) IsReadWrite() bool {
	return !l.ro
}

func (l *LockFile) TouchedSince(when time.Time) bool {
	stat, err := os.Stat(l.file)
	if err != nil {
		return true
	}
	return when.Before(stat.ModTime())
}
