# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# Todo, use os.stat_result, which contains the stat 10-tuple instead of the custom object.

from __future__ import annotations

import errno
import fnmatch
import hashlib
import os
from pathlib import Path
import pickle
import re
import sys
import stat
import time
from typing import Any

from twisted.python import log

from cowrie.core.config import CowrieConfig

(
    A_NAME,
    A_TYPE,
    A_UID,
    A_GID,
    A_SIZE,
    A_MODE,
    A_CTIME,
    A_CONTENTS,
    A_TARGET,
    A_REALFILE,
) = list(range(0, 10))
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = list(range(0, 7))


SPECIAL_PATHS: list[str] = ["/sys", "/proc", "/dev/pts"]


class _statobj:
    """
    Transform a tuple into a stat object
    """

    def __init__(
        self,
        st_mode: int,
        st_ino: int,
        st_dev: int,
        st_nlink: int,
        st_uid: int,
        st_gid: int,
        st_size: int,
        st_atime: float,
        st_mtime: float,
        st_ctime: float,
    ) -> None:
        self.st_mode: int = st_mode
        self.st_ino: int = st_ino
        self.st_dev: int = st_dev
        self.st_nlink: int = st_nlink
        self.st_uid: int = st_uid
        self.st_gid: int = st_gid
        self.st_size: int = st_size
        self.st_atime: float = st_atime
        self.st_mtime: float = st_mtime
        self.st_ctime: float = st_ctime


class TooManyLevels(Exception):
    """
    62 ELOOP Too many levels of symbolic links.  A path name lookup involved more than 8 symbolic links.
    raise OSError(errno.ELOOP, os.strerror(errno.ENOENT))
    """


class FileNotFound(Exception):
    """
    raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
    """


class PermissionDenied(Exception):
    """
    Our implementation is rather naive for now

    * TODO: Top-level /proc should return 'no such file' not 'permission
            denied'. However this seems to vary based on kernel version.

    $ sudo touch /sys/.nippon
    touch: cannot touch '/sys/.nippon': Permission denied
    $ sudo touch /proc/test
    touch: cannot touch '/proc/test': No such file or directory
    $ sudo touch /dev/pts/test
    touch: cannot touch '/dev/pts/test': Permission denied
    $ sudo touch /proc/sys/fs/binfmt_misc/.nippon
    touch: cannot touch '/proc/sys/fs/binfmt_misc/.nippon': Permission denied
    $ sudo touch /sys/fs/fuse/connections/.nippon
    touch: cannot touch '/sys/fs/fuse/connections/.nippon': Permission denied
    """


class HoneyPotFilesystem:
    def __init__(self, arch: str, home: str) -> None:
        self.fs: list[Any]

        try:
            with open(CowrieConfig.get("shell", "filesystem"), "rb") as f:
                self.fs = pickle.load(f)
        except UnicodeDecodeError:
            with open(CowrieConfig.get("shell", "filesystem"), "rb") as f:
                self.fs = pickle.load(f, encoding="utf8")
        except Exception as e:
            log.err(e, "ERROR: Failed to load filesystem")
            sys.exit(2)

        # Keep track of arch so we can return appropriate binary
        self.arch: str = arch
        self.home: str = home

        # Keep track of open file descriptors
        self.tempfiles: dict[int, str] = {}
        self.filenames: dict[int, str] = {}

        # Keep count of new files, so we can have an artificial limit
        self.newcount: int = 0

        # Get the honeyfs path from the config file and explore it for file
        # contents:
        self.init_honeyfs(CowrieConfig.get("honeypot", "contents_path"))

    def init_honeyfs(self, honeyfs_path: str) -> None:
        """
        Explore the honeyfs at 'honeyfs_path' and set all A_REALFILE attributes on
        the virtual filesystem.
        """

        for path, _directories, filenames in os.walk(honeyfs_path):
            for filename in filenames:
                realfile_path: str = os.path.join(path, filename)
                virtual_path: str = "/" + os.path.relpath(realfile_path, honeyfs_path)

                f: list[Any] | None = self.getfile(virtual_path, follow_symlinks=False)
                if f and f[A_TYPE] == T_FILE:
                    self.update_realfile(f, realfile_path)

    def resolve_path(self, pathspec: str, cwd: str) -> str:
        """
        This function does not need to be in this class, it has no dependencies
        """
        cwdpieces: list[str] = []

        # If a path within home directory is specified, convert it to an absolute path
        if pathspec.startswith("~/"):
            path = self.home + pathspec[1:]
        else:
            path = pathspec

        pieces = path.rstrip("/").split("/")

        if path[0] == "/":
            cwdpieces = []
        else:
            cwdpieces = [x for x in cwd.split("/") if len(x) and x is not None]

        while 1:
            if not pieces:
                break
            piece = pieces.pop(0)
            if piece == "..":
                if cwdpieces:
                    cwdpieces.pop()
                continue
            if piece in (".", ""):
                continue
            cwdpieces.append(piece)

        return "/{}".format("/".join(cwdpieces))

    def resolve_path_wc(self, path: str, cwd: str) -> list[str]:
        """
        Resolve_path with wildcard support (globbing)
        """
        pieces: list[str] = path.rstrip("/").split("/")
        cwdpieces: list[str]
        if len(pieces[0]):
            cwdpieces = [x for x in cwd.split("/") if len(x) and x is not None]
            path = path[1:]
        else:
            cwdpieces, pieces = [], pieces[1:]
        found: list[str] = []

        def foo(p, cwd):
            if not p:
                found.append("/{}".format("/".join(cwd)))
            elif p[0] == ".":
                foo(p[1:], cwd)
            elif p[0] == "..":
                foo(p[1:], cwd[:-1])
            else:
                names = [x[A_NAME] for x in self.get_path("/".join(cwd))]
                matches = [x for x in names if fnmatch.fnmatchcase(x, p[0])]
                for match in matches:
                    foo(p[1:], [*cwd, match])

        foo(pieces, cwdpieces)
        return found

    def get_path(self, path: str, follow_symlinks: bool = True) -> Any:
        """
        This returns the Cowrie file system objects for a directory
        """
        cwd: list[Any] = self.fs
        for part in path.split("/"):
            if not part:
                continue
            ok = False
            for c in cwd[A_CONTENTS]:
                if c[A_NAME] == part:
                    if c[A_TYPE] == T_LINK:
                        f = self.getfile(c[A_TARGET], follow_symlinks=follow_symlinks)
                        if f is None:
                            ok = False
                            break
                        else:
                            cwd = f
                    else:
                        cwd = c
                    ok = True
                    break
            if not ok:
                raise FileNotFound
        return cwd[A_CONTENTS]

    def exists(self, path: str) -> bool:
        """
        Return True if path refers to an existing path.
        Returns False for broken symbolic links.
        """
        f: list[Any] | None = self.getfile(path, follow_symlinks=True)
        if f is not None:
            return True
        return False

    def lexists(self, path: str) -> bool:
        """
        Return True if path refers to an existing path.
        Returns True for broken symbolic links.
        """
        f: list[Any] | None = self.getfile(path, follow_symlinks=False)
        if f is not None:
            return True
        return False

    def update_realfile(self, f: Any, realfile: str) -> None:
        if (
            not f[A_REALFILE]
            and os.path.exists(realfile)
            and not os.path.islink(realfile)
            and os.path.isfile(realfile)
            and f[A_SIZE] < 25000000
        ):
            f[A_REALFILE] = realfile

    def getfile(self, path: str, follow_symlinks: bool = True) -> list[Any] | None:
        """
        This returns the Cowrie file system object for a path.
        """
        if path == "/":
            return self.fs

        pieces: list[str] = path.strip("/").split("/")
        cwd: list[Any] | None = self.fs

        for piece in pieces:
            if not isinstance(cwd, list):
                log.msg(f"DEBUG [getfile]: Unexpected type for cwd: {type(cwd)}. Returning None.")
                return None

            try:
                # Check if the piece exists in the current directory's contents
                cwd_contents = cwd[A_CONTENTS] if len(cwd) > A_CONTENTS else []
                if piece not in [x[A_NAME] for x in cwd_contents if isinstance(x, list) and len(x) > A_NAME]:
                    log.msg(f"DEBUG [getfile]: '{piece}' not found in current directory.")
                    return None

                # Navigate to the next level in the path
                for x in cwd_contents:
                    if x[A_NAME] == piece:
                        if piece == pieces[-1] and not follow_symlinks:
                            return x
                        if x[A_TYPE] == T_LINK:
                            # Handle symbolic links
                            target = x[A_TARGET]
                            fileobj = self.getfile(
                                target if target.startswith("/") else "/".join((path, target)),
                                follow_symlinks=follow_symlinks
                            )
                            if fileobj:
                                cwd = fileobj
                            else:
                                log.msg(f"DEBUG [getfile]: Broken symbolic link at '{piece}'.")
                                return None
                        else:
                            cwd = x
                        break
            except IndexError as e:
                log.msg(f"ERROR [getfile]: IndexError for path '{path}' at piece '{piece}': {e}")
                return None
        return cwd


    def file_contents(self, target: str) -> bytes:
        """
        Retrieve the content of a file in the honeyfs
        It follows links.
        It tries A_REALFILE first and then tries honeyfs directory
        Then return the executable header for executables
        """
        path: str = self.resolve_path(target, os.path.dirname(target))
        if not path or not self.exists(path):
            raise FileNotFound
        f: Any = self.getfile(path)
        if f[A_TYPE] == T_DIR:
            raise IsADirectoryError
        if f[A_TYPE] == T_FILE and f[A_REALFILE]:
            return Path(f[A_REALFILE]).read_bytes()
        if f[A_TYPE] == T_FILE and f[A_SIZE] == 0:
            # Zero-byte file lacking A_REALFILE backing: probably empty.
            # (The exceptions to this are some system files in /proc and /sys,
            # but it's likely better to return nothing than suspiciously fail.)
            return b""
        if f[A_TYPE] == T_FILE and f[A_MODE] & stat.S_IXUSR:
            return open(
                CowrieConfig.get("honeypot", "share_path") + "/arch/" + self.arch,
                "rb",
            ).read()
        return b""

    def mkfile(
        self,
        path: str,
        uid: int,
        gid: int,
        size: int,
        mode: int,
        ctime: float | None = None,
    ) -> bool:
        if self.newcount > 10000:
            return False
        if ctime is None:
            ctime = time.time()
        _path: str = os.path.dirname(path)

        if any([_path.startswith(_p) for _p in SPECIAL_PATHS]):
            raise PermissionDenied

        _dir = self.get_path(_path)
        outfile: str = os.path.basename(path)
        if outfile in [x[A_NAME] for x in _dir]:
            _dir.remove(next(x for x in _dir if x[A_NAME] == outfile))
        _dir.append([outfile, T_FILE, uid, gid, size, mode, ctime, [], None, None])
        self.newcount += 1
        return True

    def mkdir(
        self,
        path: str,
        uid: int,
        gid: int,
        size: int,
        mode: int,
        ctime: float | None = None,
        user_created: bool = True,  # Add explicit `user_created` parameter
    ) -> None:
        """
        Create a new directory in the virtual filesystem and persist it to fs.pickle.
        """
        if self.newcount > 10000:
            raise OSError(errno.EDQUOT, os.strerror(errno.EDQUOT), path)
        if ctime is None:
            ctime = time.time()
        if not path.strip("/"):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        try:
            # Resolve parent directory
            directory = self.get_path(os.path.dirname(path.strip("/")))
        except IndexError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path) from None

        # Append the new directory with user_created flag
        directory.append(
            [os.path.basename(path), T_DIR, uid, gid, size, mode, ctime, [], None, None, user_created]  # Use the `user_created` parameter
        )
        log.msg(f"DEBUG: Directory structure in memory: {directory}")
        log.msg(f"DEBUG [mkdir]: Added entry - Type: {type(directory[-1])}, Content: {directory[-1]}")
        self.newcount += 1

        log.msg(
            f"DEBUG: Created directory '{path}' with user_created={user_created} in memory."
        )

        # Persist changes to fs.pickle
        pickle_file = CowrieConfig.get("shell", "filesystem")
        try:
            with open(pickle_file, "wb") as f:
                pickle.dump(self.fs, f)
                log.msg(f"DEBUG: Persisted changes to fs.pickle: {self.fs}")
        except Exception as e:
            log.err(f"ERROR: Failed to persist changes to fs.pickle: {e}")



    def isfile(self, path: str) -> bool:
        """
        Return True if path is an existing regular file. This follows symbolic
        links, so both islink() and isfile() can be true for the same path.
        """
        try:
            f: list[Any] | None = self.getfile(path)
        except Exception:
            return False
        if f is None:
            return False
        if f[A_TYPE] == T_FILE:
            return True
        return False

    def islink(self, path: str) -> bool:
        """
        Return True if path refers to a directory entry that is a symbolic
        link. Always False if symbolic links are not supported by the python
        runtime.
        """
        try:
            f: list[Any] | None = self.getfile(path)
        except Exception:
            return False
        if f is None:
            return False
        if f[A_TYPE] == T_LINK:
            return True
        return False

    def isdir(self, path: str) -> bool:
        """
        Return True if path is an existing directory.
        This follows symbolic links, so both islink() and isdir() can be true for the same path.
        """
        if path == "/":
            return True
        try:
            directory = self.getfile(path)
        except Exception:
            directory = None
        if directory is None:
            return False
        if directory[A_TYPE] == T_DIR:
            return True
        return False

    # Below additions for SFTP support, try to keep functions here similar to os.*

    def open(self, filename: str, openFlags: int, mode: int) -> int | None:
        """
        #log.msg("fs.open %s" % filename)

        #if (openFlags & os.O_APPEND == os.O_APPEND):
        #    log.msg("fs.open append")

        #if (openFlags & os.O_CREAT == os.O_CREAT):
        #    log.msg("fs.open creat")

        #if (openFlags & os.O_TRUNC == os.O_TRUNC):
        #    log.msg("fs.open trunc")

        #if (openFlags & os.O_EXCL == os.O_EXCL):
        #    log.msg("fs.open excl")

        # treat O_RDWR same as O_WRONLY
        """
        if openFlags & os.O_WRONLY == os.O_WRONLY or openFlags & os.O_RDWR == os.O_RDWR:
            # strip executable bit
            hostmode: int = mode & ~(111)
            hostfile: str = "{}/{}_sftp_{}".format(
                CowrieConfig.get("honeypot", "download_path"),
                time.strftime("%Y%m%d-%H%M%S"),
                re.sub("[^A-Za-z0-9]", "_", filename),
            )
            self.mkfile(filename, 0, 0, 0, stat.S_IFREG | mode)
            fd = os.open(hostfile, openFlags, hostmode)
            self.update_realfile(self.getfile(filename), hostfile)
            self.tempfiles[fd] = hostfile
            self.filenames[fd] = filename
            return fd

        # TODO: throw exception
        if openFlags & os.O_RDONLY == os.O_RDONLY:
            return None

        # TODO: throw exception
        return None

    def read(self, fd: int, n: int) -> bytes:
        # this should not be called, we intercept at readChunk
        raise NotImplementedError

    def write(self, fd: int, string: bytes) -> int:
        return os.write(fd, string)

    def close(self, fd: int) -> None:
        if not fd:
            return
        if self.tempfiles[fd] is not None:
            with open(self.tempfiles[fd], "rb") as f:
                shasum: str = hashlib.sha256(f.read()).hexdigest()
            shasumfile: str = (
                CowrieConfig.get("honeypot", "download_path") + "/" + shasum
            )
            if os.path.exists(shasumfile):
                os.remove(self.tempfiles[fd])
            else:
                os.rename(self.tempfiles[fd], shasumfile)
            self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)
            log.msg(
                format='SFTP Uploaded file "%(filename)s" to %(outfile)s',
                eventid="cowrie.session.file_upload",
                filename=os.path.basename(self.filenames[fd]),
                outfile=shasumfile,
                shasum=shasum,
            )
            del self.tempfiles[fd]
            del self.filenames[fd]
        os.close(fd)

    def lseek(self, fd: int, offset: int, whence: int) -> int:
        if not fd:
            return True
        return os.lseek(fd, offset, whence)

    def mkdir2(self, path: str) -> None:
        """
        FIXME mkdir() name conflicts with existing mkdir
        """
        directory: list[Any] | None = self.getfile(path)
        if directory:
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), path)
        self.mkdir(path, 0, 0, 4096, 16877)

    def rmdir(self, path: str) -> bool:
        """
        Remove a user-created directory from the virtual filesystem and persist changes.
        """
        p: str = path.rstrip("/")
        name: str = os.path.basename(p)
        parent: str = os.path.dirname(p)

        try:
            # Get the directory object
            directory = self.getfile(p, follow_symlinks=False)
        except FileNotFoundError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), p)

        # Validate the directory type
        if directory[A_TYPE] != T_DIR:
            log.msg(f"ERROR: '{p}' is not a directory. Cannot remove.")
            raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), p)

        # Check if the directory is empty
        if len(self.get_path(p)) > 0:
            log.msg(f"DEBUG: Directory '{p}' is not empty. Cannot remove.")
            raise OSError(errno.ENOTEMPTY, os.strerror(errno.ENOTEMPTY), p)

        # Check the user_created flag for directories with 11 entries
        if len(directory) == 11:
            if not directory[-1]:
                log.msg(f"DEBUG: Directory '{p}' is not user-created. Skipping removal.")
                raise OSError(errno.EPERM, "Operation not permitted", p)
        elif len(directory) == 10:
            log.msg(f"WARNING: Directory '{p}' has no user_created flag. Treating as non-user-created.")
            raise OSError(errno.EPERM, "Operation not permitted", p)
        else:
            log.msg(f"ERROR: Malformed directory structure for '{p}'. Cannot remove.")
            raise OSError(errno.EINVAL, "Malformed directory entry", p)

        # Attempt to remove the directory from its parent
        try:
            parent_dir = self.get_path(parent, follow_symlinks=True)
            if not isinstance(parent_dir, list):
                raise ValueError(f"Invalid parent directory structure for '{p}'")

            for i in parent_dir[:]:
                if i[A_NAME] == name:
                    parent_dir.remove(i)
                    log.msg(f"DEBUG: Successfully removed directory '{p}' from memory.")
                    break
            else:
                log.msg(f"ERROR: Directory '{p}' not found in parent. Cannot remove.")
                raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), p)

        except Exception as e:
            log.err(f"ERROR: Failed to remove directory '{p}' from memory: {e}")
            raise

        # Backup current filesystem state
        pickle_file = CowrieConfig.get("shell", "filesystem")
        backup_fs = self.fs.copy()

        # Persist changes to fs.pickle
        try:
            with open(pickle_file, "wb") as f:
                pickle.dump(self.fs, f)
                log.msg(f"DEBUG: Persisted updated filesystem to fs.pickle after removing '{p}'")
        except Exception as e:
            # Restore from backup if persistence fails
            self.fs = backup_fs
            log.err(f"ERROR: Failed to persist changes to fs.pickle: {e}")
            raise

        return True


    def utime(self, path: str, _atime: float, mtime: float) -> None:
        p: list[Any] | None = self.getfile(path)
        if not p:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        p[A_CTIME] = mtime

    def chmod(self, path: str, perm: int) -> None:
        p: list[Any] | None = self.getfile(path)
        if not p:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        p[A_MODE] = stat.S_IFMT(p[A_MODE]) | perm

    def chown(self, path: str, uid: int, gid: int) -> None:
        p: list[Any] | None = self.getfile(path)
        if not p:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if uid != -1:
            p[A_UID] = uid
        if gid != -1:
            p[A_GID] = gid

    def remove(self, path: str) -> None:
        p: list[Any] | None = self.getfile(path, follow_symlinks=False)
        if not p:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        self.get_path(os.path.dirname(path)).remove(p)

    def readlink(self, path: str) -> str:
        p: list[Any] | None = self.getfile(path, follow_symlinks=False)
        if not p:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if not p[A_MODE] & stat.S_IFLNK:
            raise OSError
        return p[A_TARGET]  # type: ignore

    def symlink(self, targetPath: str, linkPath: str) -> None:
        raise NotImplementedError

    def rename(self, oldpath: str, newpath: str) -> None:
        old: list[Any] | None = self.getfile(oldpath)
        if not old:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        new = self.getfile(newpath)
        if new:
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST))

        self.get_path(os.path.dirname(oldpath)).remove(old)
        old[A_NAME] = os.path.basename(newpath)
        self.get_path(os.path.dirname(newpath)).append(old)

    def listdir(self, path: str) -> list[str]:
        names: list[str] = [x[A_NAME] for x in self.get_path(path)]
        return names

    def lstat(self, path: str) -> _statobj:
        return self.stat(path, follow_symlinks=False)

    def stat(self, path: str, follow_symlinks: bool = True) -> _statobj:
        p: list[Any] | None
        if path == "/":
            p = []
            p[A_TYPE] = T_DIR
            p[A_UID] = 0
            p[A_GID] = 0
            p[A_SIZE] = 4096
            p[A_MODE] = 16877
            p[A_CTIME] = time.time()
        else:
            p = self.getfile(path, follow_symlinks=follow_symlinks)

        if not p:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        return _statobj(
            p[A_MODE],
            0,
            0,
            1,
            p[A_UID],
            p[A_GID],
            p[A_SIZE],
            p[A_CTIME],
            p[A_CTIME],
            p[A_CTIME],
        )

    def realpath(self, path: str) -> str:
        return path

    def update_size(self, filename: str, size: int) -> None:
        f: list[Any] | None = self.getfile(filename)
        if not f:
            return
        if f[A_TYPE] != T_FILE:
            return
        f[A_SIZE] = size
