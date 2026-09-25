#!/usr/bin/env python3
# tests/alpha-lima-matrix.py — the mounted write-path matrix for the Lima
# e2e (guest step 3). Precise fd-level cases bash cannot express
# (O_EXCL, O_APPEND|O_TRUNC, stale handles, append ordering). Each case
# asserts observable behavior only: errnos, file content, stat bits.
# Snapshot counts are deliberately never asserted — one flush may legally
# become many or (under a future transaction window) coalesce; the suite
# pins content, durability, and monotonicity instead.
#
# Usage: python3 tests/alpha-lima-matrix.py <mountpoint>
import errno
import os
import sys

MNT = sys.argv[1]
passed = []


def check(name, fn):
    try:
        fn()
    except AssertionError as e:
        print("MATRIX FAIL: " + name + ": " + str(e))
        sys.exit(1)
    except OSError as e:
        print("MATRIX FAIL: %s: unexpected OSError %d (%s)" % (
            name, e.errno, errno.errorcode.get(e.errno, "?")))
        sys.exit(1)
    passed.append(name)
    print("  PASS: matrix: " + name)


def expect_errno(name, want, fn):
    try:
        fn()
    except OSError as e:
        assert e.errno == want, "%s: errno %d (%s), want %d (%s)" % (
            name, e.errno, errno.errorcode.get(e.errno, "?"),
            want, errno.errorcode.get(want, "?"))
        return
    raise AssertionError(name + ": succeeded, want errno " + str(want))


def p(*parts):
    return os.path.join(MNT, *parts)


def close_after_failed_commit(fd):
    # Release replays the failed commit best-effort, so close reports
    # the same EIO the committing boundary already returned. Pin it:
    # silently swallowing the close error would hide the failure.
    try:
        os.close(fd)
    except OSError as e:
        assert e.errno == errno.EIO, "close after failed commit: errno %d" % e.errno
        return
    raise AssertionError("close after failed commit succeeded")


def read(path):
    with open(path, "rb") as f:
        return f.read()


def commit_write(path, data, flags=os.O_WRONLY):
    fd = os.open(path, flags)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


# --- namespace surface ---------------------------------------------------
def c_mkdir_no_intermediates():
    expect_errno("mkdir", errno.ENOENT, lambda: os.mkdir(p("m", "no", "parent")))


def c_mkdir_eexist():
    os.mkdir(p("m", "dup"))
    expect_errno("mkdir", errno.EEXIST, lambda: os.mkdir(p("m", "dup")))


def c_mkdir_predecessor():
    # Each mutation evaluates against its predecessor's commit: the second
    # mkdir of the same name fails even though both raced nothing.
    os.mkdir(p("m", "pred"))
    expect_errno("mkdir", errno.EEXIST, lambda: os.mkdir(p("m", "pred")))


def c_create_oexcl():
    commit_write(p("m", "excl"), b"x", os.O_WRONLY | os.O_CREAT)
    expect_errno("open", errno.EEXIST,
                 lambda: os.open(p("m", "excl"), os.O_WRONLY | os.O_CREAT | os.O_EXCL))


def c_unlink_missing():
    expect_errno("unlink", errno.ENOENT, lambda: os.unlink(p("m", "ghost")))


def c_unlink_dir():
    expect_errno("unlink", errno.EISDIR, lambda: os.unlink(p("m", "dup")))


def c_rmdir_file():
    expect_errno("rmdir", errno.ENOTDIR, lambda: os.rmdir(p("m", "excl")))


def c_rmdir_nonempty():
    expect_errno("rmdir", errno.ENOTEMPTY, lambda: os.rmdir(p("m")))


def c_write_dir():
    # Write access on a directory fails: the open itself is refused since
    # directories are never writable handles.
    expect_errno("open", errno.EISDIR,
                 lambda: os.open(p("m", "dup"), os.O_WRONLY))


def c_write_readonly():
    fd = os.open(p("m", "excl"), os.O_RDONLY)
    try:
        expect_errno("write", errno.EBADF, lambda: os.write(fd, b"x"))
    finally:
        os.close(fd)


def c_symlink_refused():
    expect_errno("symlink", errno.EOPNOTSUPP,
                 lambda: os.symlink("target", p("m", "link")))


def c_hardlink_refused():
    expect_errno("link", errno.EOPNOTSUPP,
                 lambda: os.link(p("m", "excl"), p("m", "hard")))


def c_xattr_refused():
    path = p("m", "excl")
    expect_errno("setxattr", errno.EOPNOTSUPP,
                 lambda: os.setxattr(path, "user.e2e", b"v"))
    expect_errno("getxattr", errno.EOPNOTSUPP,
                 lambda: os.getxattr(path, "user.e2e"))
    expect_errno("listxattr", errno.EOPNOTSUPP,
                 lambda: os.listxattr(path))


def c_append_trunc_refused():
    expect_errno("open", errno.EOPNOTSUPP, lambda: os.open(
        p("m", "excl"), os.O_WRONLY | os.O_APPEND | os.O_TRUNC))


def c_offset_overflow():
    # Through real syscalls the kernel preempts offset overflow with
    # EINVAL before FUSE is reached; the mount's own checked arithmetic
    # (EFBIG) is pinned by a daemon unit test instead.
    fd = os.open(p("m", "excl"), os.O_WRONLY)
    try:
        os.lseek(fd, (1 << 63) - 8, os.SEEK_SET)
        expect_errno("write", errno.EINVAL, lambda: os.write(fd, b"12345678"))
    finally:
        os.close(fd)


def c_pwrite_beyond_eof():
    path = p("m", "sparse")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT)
    try:
        os.lseek(fd, 8, os.SEEK_SET)
        os.write(fd, b"tail")
        os.fsync(fd)
    finally:
        os.close(fd)
    assert read(path) == b"\x00" * 8 + b"tail", "hole not zero-filled"


def c_chmod_exec_only():
    path = p("m", "mode")
    commit_write(path, b"x", os.O_WRONLY | os.O_CREAT)
    os.chmod(path, 0o755)
    assert os.stat(path).st_mode & 0o777 == 0o755, "exec bit not stored"
    os.chmod(path, 0o600)
    assert os.stat(path).st_mode & 0o777 == 0o644, "unsupported bits persisted"
    assert read(path) == b"x", "chmod changed content"


# --- rename matrix -------------------------------------------------------
def c_rename_file_file():
    commit_write(p("m", "rn-a"), b"A", os.O_WRONLY | os.O_CREAT)
    commit_write(p("m", "rn-b"), b"B", os.O_WRONLY | os.O_CREAT)
    os.rename(p("m", "rn-a"), p("m", "rn-b"))
    assert read(p("m", "rn-b")) == b"A", "rename did not replace"


def c_rename_file_dir():
    expect_errno("rename", errno.EISDIR,
                 lambda: os.rename(p("m", "excl"), p("m", "dup")))


def c_rename_dir_empty():
    os.mkdir(p("m", "rd1"))
    os.mkdir(p("m", "rd2"))
    os.rename(p("m", "rd1"), p("m", "rd2"))
    assert os.path.isdir(p("m", "rd2")), "dir rename lost the target"


def c_rename_dir_nonempty():
    os.mkdir(p("m", "rd3"))
    expect_errno("rename", errno.ENOTEMPTY,
                 lambda: os.rename(p("m", "rd3"), p("m")))


def c_rename_dir_file():
    expect_errno("rename", errno.ENOTDIR,
                 lambda: os.rename(p("m", "dup"), p("m", "excl")))


def c_rename_into_descendant():
    expect_errno("rename", errno.EINVAL,
                 lambda: os.rename(p("m"), p("m", "dup", "deeper")))


def c_rename_same_path():
    commit_write(p("m", "same"), b"S", os.O_WRONLY | os.O_CREAT)
    os.rename(p("m", "same"), p("m", "same"))
    assert read(p("m", "same")) == b"S", "same-path rename is not a no-op"


def c_rename_cross_dir():
    os.mkdir(p("m", "xd"))
    commit_write(p("m", "xd", "f"), b"X", os.O_WRONLY | os.O_CREAT)
    os.rename(p("m", "xd", "f"), p("m", "f-moved"))
    assert read(p("m", "f-moved")) == b"X", "cross-dir rename lost content"


# --- commit boundaries ---------------------------------------------------
def c_buffer_no_commit():
    path = p("m", "buf")
    commit_write(path, b"old", os.O_WRONLY | os.O_CREAT)
    fd = os.open(path, os.O_RDWR)
    try:
        os.write(fd, b"new")
        # Same-handle reads see the overlay; other opens see the head.
        assert os.pread(fd, 3, 0) == b"new", "no read-your-writes"
        assert read(path) == b"old", "uncommitted write visible"
        os.fsync(fd)
    finally:
        os.close(fd)
    assert read(path) == b"new", "flush did not commit"


def c_clean_flush_noop():
    path = p("m", "clean")
    commit_write(path, b"C", os.O_WRONLY | os.O_CREAT)
    fd = os.open(path, os.O_WRONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    assert read(path) == b"C", "clean flush changed content"


def c_otrunc_defers():
    # O_TRUNC commits during open (the kernel delivers it as open plus
    # a separate setattr, so deferring to flush would stale every
    # trunc handle): a fresh open already sees the empty file, and the
    # handle commits later writes against the post-truncate base.
    path = p("m", "tr")
    commit_write(path, b"keepme", os.O_WRONLY | os.O_CREAT)
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        assert read(path) == b"", "O_TRUNC not visible at open"
        os.write(fd, b"new")
        os.fsync(fd)
    finally:
        os.close(fd)
    assert read(path) == b"new", "write after O_TRUNC lost"


def c_otrunc_stale():
    # A clean handle's flush is a no-op success even after a
    # concurrent change; staleness bites when the handle has content
    # to commit.
    path = p("m", "trs")
    commit_write(path, b"v1", os.O_WRONLY | os.O_CREAT)
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC)
    try:
        commit_write(path, b"v2-changed")
        os.fsync(fd)
        os.write(fd, b"v3")
        expect_errno("fsync", errno.EIO, lambda: os.fsync(fd))
    finally:
        close_after_failed_commit(fd)
    assert read(path) == b"v2-changed", "stale truncation won"


def c_failed_commit_terminal():
    path = p("m", "term")
    commit_write(path, b"T1", os.O_WRONLY | os.O_CREAT)
    fd = os.open(path, os.O_WRONLY)
    try:
        os.write(fd, b"T-stale")
        commit_write(path, b"T2")
        expect_errno("fsync", errno.EIO, lambda: os.fsync(fd))
        # The handle is terminal: no retry of the old buffer.
        try:
            os.fsync(fd)
        except OSError:
            pass
        else:
            raise AssertionError("second commit on a failed handle succeeded")
    finally:
        close_after_failed_commit(fd)
    assert read(path) == b"T2", "failed handle overwrote the winner"


# --- lost-update boundary ------------------------------------------------
def c_stale_handle():
    path = p("m", "st")
    commit_write(path, b"AAAA", os.O_WRONLY | os.O_CREAT)
    fa = os.open(path, os.O_WRONLY)
    fb = os.open(path, os.O_WRONLY)
    try:
        os.write(fb, b"BBBB")
        os.fsync(fb)
        os.write(fa, b"CCCC")
        expect_errno("fsync", errno.EIO, lambda: os.fsync(fa))
    finally:
        close_after_failed_commit(fa)
        os.close(fb)
    assert read(path) == b"BBBB", "loser overwrote the winner"


def c_concurrent_partial():
    path = p("m", "pw")
    commit_write(path, b"\x00" * 200, os.O_WRONLY | os.O_CREAT)
    fa = os.open(path, os.O_WRONLY)
    fb = os.open(path, os.O_WRONLY)
    loser = None
    try:
        os.pwrite(fa, b"A" * 10, 0)
        os.pwrite(fb, b"B" * 10, 100)
        os.fsync(fa)
        try:
            os.fsync(fb)
            winner = "B"
        except OSError as e:
            assert e.errno == errno.EIO, "loser errno %d" % e.errno
            winner = "A"
            loser = fb
    finally:
        os.close(fa)
        if loser is None:
            os.close(fb)
        else:
            close_after_failed_commit(fb)
    body = read(path)
    if winner == "B":
        assert body == b"\x00" * 100 + b"B" * 10 + b"\x00" * 90, "no silent merge"
    else:
        assert body == b"A" * 10 + b"\x00" * 190, "no silent merge"


def c_different_path_rebase():
    commit_write(p("m", "x"), b"X0", os.O_WRONLY | os.O_CREAT)
    fx = os.open(p("m", "x"), os.O_WRONLY)
    try:
        commit_write(p("m", "y"), b"Y1", os.O_WRONLY | os.O_CREAT)
        os.write(fx, b"X1")
        os.fsync(fx)
    finally:
        os.close(fx)
    assert read(p("m", "x")) == b"X1", "rebase lost X"
    assert read(p("m", "y")) == b"Y1", "rebase lost Y"


def c_append_ordering():
    path = p("m", "ap")
    commit_write(path, b"old", os.O_WRONLY | os.O_CREAT)
    fa = os.open(path, os.O_WRONLY | os.O_APPEND)
    fb = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fa, b"A")
        os.write(fb, b"B")
        os.fsync(fa)
        os.fsync(fb)
    finally:
        os.close(fa)
        os.close(fb)
    assert read(path) == b"oldAB", "append order wrong: %r" % read(path)


def c_append_intervening():
    path = p("m", "api")
    commit_write(path, b"AAAA", os.O_WRONLY | os.O_CREAT)
    fa = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        commit_write(path, b"BBBB")
        os.write(fa, b"X")
        os.fsync(fa)
    finally:
        os.close(fa)
    assert read(path) == b"BBBBX", "append rejected the intervening write"


def c_append_after_removal():
    path = p("m", "apr")
    commit_write(path, b"gone", os.O_WRONLY | os.O_CREAT)
    fa = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.unlink(path)
        os.write(fa, b"X")
        expect_errno("fsync", errno.EIO, lambda: os.fsync(fa))
    finally:
        close_after_failed_commit(fa)


def c_rename_breaks_handle():
    commit_write(p("m", "rb"), b"R", os.O_WRONLY | os.O_CREAT)
    fd = os.open(p("m", "rb"), os.O_WRONLY)
    try:
        os.rename(p("m", "rb"), p("m", "rb2"))
        assert read(p("m", "rb2")) == b"R", "rename lost content"
        os.write(fd, b"R2")
        expect_errno("fsync", errno.EIO, lambda: os.fsync(fd))
    finally:
        close_after_failed_commit(fd)


def c_unlink_breaks_handle():
    commit_write(p("m", "ub"), b"U", os.O_WRONLY | os.O_CREAT)
    fd = os.open(p("m", "ub"), os.O_WRONLY)
    try:
        os.unlink(p("m", "ub"))
        os.write(fd, b"U2")
        expect_errno("fsync", errno.EIO, lambda: os.fsync(fd))
    finally:
        close_after_failed_commit(fd)


def c_read_capture_survives_unlink():
    commit_write(p("m", "rc"), b"CAP", os.O_WRONLY | os.O_CREAT)
    fd = os.open(p("m", "rc"), os.O_RDONLY)
    try:
        os.unlink(p("m", "rc"))
        assert os.read(fd, 3) == b"CAP", "read capture did not survive unlink"
    finally:
        os.close(fd)


CASES = [
    c_mkdir_no_intermediates, c_mkdir_eexist, c_mkdir_predecessor,
    c_create_oexcl, c_unlink_missing, c_unlink_dir, c_rmdir_file,
    c_rmdir_nonempty, c_write_dir, c_write_readonly, c_symlink_refused,
    c_hardlink_refused, c_xattr_refused,
    c_append_trunc_refused, c_offset_overflow, c_pwrite_beyond_eof,
    c_chmod_exec_only, c_rename_file_file, c_rename_file_dir,
    c_rename_dir_empty, c_rename_dir_nonempty, c_rename_dir_file,
    c_rename_into_descendant, c_rename_same_path, c_rename_cross_dir,
    c_buffer_no_commit, c_clean_flush_noop, c_otrunc_defers, c_otrunc_stale,
    c_failed_commit_terminal, c_stale_handle, c_concurrent_partial,
    c_different_path_rebase, c_append_ordering, c_append_intervening,
    c_append_after_removal, c_rename_breaks_handle, c_unlink_breaks_handle,
    c_read_capture_survives_unlink,
]

os.makedirs(p("m"), exist_ok=True)
for case in CASES:
    check(case.__name__[2:], case)
print("matrix: %d cases passed" % len(passed))
