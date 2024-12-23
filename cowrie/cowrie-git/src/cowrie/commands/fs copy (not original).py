# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


"""
Filesystem related commands
"""

from __future__ import annotations

import copy
import getopt
import os.path
import re
from collections.abc import Callable

import pickle
import time
from cowrie.core.config import CowrieConfig

from twisted.python import log
from os.path import normpath

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands: dict[str, Callable] = {}

def is_valid_entry(entry: list) -> bool:
    """
    Validate the structure of a directory entry in fs.pickle.
    """
    log.msg(f"DEBUG [is_valid_entry]: Entry type: {type(entry)}, Entry content: {entry}")
    if not isinstance(entry, list):
        log.msg(f"DEBUG: Invalid entry skipped - Not a list. Entry: {entry}")
        return False
    if len(entry) < 10:
        log.msg(f"DEBUG: Invalid entry skipped - Insufficient fields. Entry: {entry}")
        return False
    if len(entry) > 10 and entry[-1] not in [True, False, None]:
        log.msg(f"DEBUG: Invalid entry skipped - Incorrect user_created flag. Entry: {entry}")
        return False
    return True

class Command_grep(HoneyPotCommand):
    """
    grep command
    """

    def grep_get_contents(self, filename: str, match: str) -> None:
        try:
            contents = self.fs.file_contents(filename)
            self.grep_application(contents, match)
        except Exception:
            self.errorWrite(f"grep: {filename}: No such file or directory\n")

    def grep_application(self, contents: bytes, match: str) -> None:
        bmatch = os.path.basename(match).replace('"', "").encode("utf8")
        matches = re.compile(bmatch)
        contentsplit = contents.split(b"\n")
        for line in contentsplit:
            if matches.search(line):
                self.writeBytes(line + b"\n")

    def help(self) -> None:
        self.writeBytes(
            b"usage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ] [-A num] [-B num] [-C[num]]\n"
        )
        self.writeBytes(
            b"\t[-e pattern] [-f file] [--binary-files=value] [--color=when]\n"
        )
        self.writeBytes(
            b"\t[--context[=num]] [--directories=action] [--label] [--line-buffered]\n"
        )
        self.writeBytes(b"\t[--null] [pattern] [file ...]\n")

    def start(self) -> None:
        if not self.args:
            self.help()
            self.exit()
            return

        self.n = 10
        if self.args[0] == ">":
            pass
        else:
            try:
                optlist, args = getopt.getopt(
                    self.args, "abcDEFGHhIiJLlmnOoPqRSsUVvwxZA:B:C:e:f:"
                )
            except getopt.GetoptError as err:
                self.errorWrite(f"grep: invalid option -- {err.opt}\n")
                self.help()
                self.exit()
                return

            for opt, _arg in optlist:
                if opt == "-h":
                    self.help()

        if not self.input_data:
            files = self.check_arguments("grep", args[1:])
            for pname in files:
                self.grep_get_contents(pname, args[0])
        else:
            self.grep_application(self.input_data, args[0])

        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="grep",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def handle_CTRL_D(self) -> None:
        self.exit()


commands["/bin/grep"] = Command_grep
commands["grep"] = Command_grep
commands["/bin/egrep"] = Command_grep
commands["/bin/fgrep"] = Command_grep


class Command_tail(HoneyPotCommand):
    """
    tail command
    """

    n: int = 10

    def tail_get_contents(self, filename: str) -> None:
        try:
            contents = self.fs.file_contents(filename)
            self.tail_application(contents)
        except Exception:
            self.errorWrite(
                f"tail: cannot open `{filename}' for reading: No such file or directory\n"
            )

    def tail_application(self, contents: bytes) -> None:
        contentsplit = contents.split(b"\n")
        lines = int(len(contentsplit))
        if lines < self.n:
            self.n = lines - 1
        i = 0
        for j in range((lines - self.n - 1), lines):
            self.writeBytes(contentsplit[j])
            if i < self.n:
                self.write("\n")
            i += 1

    def start(self) -> None:
        if not self.args or self.args[0] == ">":
            return
        else:
            try:
                optlist, args = getopt.getopt(self.args, "n:")
            except getopt.GetoptError as err:
                self.errorWrite(f"tail: invalid option -- '{err.opt}'\n")
                self.exit()
                return

            for opt in optlist:
                if opt[0] == "-n":
                    if not opt[1].isdigit():
                        self.errorWrite(f"tail: illegal offset -- {opt[1]}\n")
                    else:
                        self.n = int(opt[1])
        if not self.input_data:
            files = self.check_arguments("tail", args)
            for pname in files:
                self.tail_get_contents(pname)
        else:
            self.tail_application(self.input_data)

        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="tail",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def handle_CTRL_D(self) -> None:
        self.exit()


commands["/bin/tail"] = Command_tail
commands["/usr/bin/tail"] = Command_tail
commands["tail"] = Command_tail


class Command_head(HoneyPotCommand):
    """
    head command
    """

    linecount: int = 10
    bytecount: int = 0

    def head_application(self, contents: bytes) -> None:
        if self.bytecount:
            self.writeBytes(contents[: self.bytecount])
        elif self.linecount:
            linesplit = contents.split(b"\n")
            for line in linesplit[: self.linecount]:
                self.writeBytes(line + b"\n")

    def head_get_file_contents(self, filename: str) -> None:
        try:
            contents = self.fs.file_contents(filename)
            self.head_application(contents)
        except fs.FileNotFound:
            self.errorWrite(
                f"head: cannot open `{filename}' for reading: No such file or directory\n"
            )

    def start(self) -> None:
        self.lines: int = 10
        self.bytecount: int = 0
        if not self.args or self.args[0] == ">":
            return
        else:
            try:
                optlist, args = getopt.getopt(self.args, "c:n:")
            except getopt.GetoptError as err:
                self.errorWrite(f"head: invalid option -- '{err.opt}'\n")
                self.exit()
                return

            for opt in optlist:
                if opt[0] == "-n":
                    if not opt[1].isdigit():
                        self.errorWrite(f"head: invalid number of lines: `{opt[1]}`\n")
                    else:
                        self.linecount = int(opt[1])
                        self.bytecount = 0
                elif opt[0] == "-c":
                    if not opt[1].isdigit():
                        self.errorWrite(f"head: invalid number of bytes: `{opt[1]}`\n")
                    else:
                        self.bytecount = int(opt[1])
                        self.linecount = 0

        if not self.input_data:
            files = self.check_arguments("head", args)
            for pname in files:
                self.head_get_file_contents(pname)
        else:
            self.head_application(self.input_data)
        self.exit()

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.command.input",
            realm="head",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def handle_CTRL_D(self) -> None:
        self.exit()


commands["/bin/head"] = Command_head
commands["/usr/bin/head"] = Command_head
commands["head"] = Command_head


class Command_cd(HoneyPotCommand):
    """
    cd command
    """

    def call(self) -> None:
        if not self.args or self.args[0] == "~":
            pname = self.protocol.user.avatar.home
        else:
            pname = self.args[0]
        try:
            newpath = self.fs.resolve_path(pname, self.protocol.cwd)
            inode = self.fs.getfile(newpath)
        except Exception:
            inode = None
        if pname == "-":
            self.errorWrite("bash: cd: OLDPWD not set\n")
            return
        if inode is None or inode is False:
            self.errorWrite(f"bash: cd: {pname}: No such file or directory\n")
            return
        if inode[fs.A_TYPE] != fs.T_DIR:
            self.errorWrite(f"bash: cd: {pname}: Not a directory\n")
            return
        self.protocol.cwd = newpath


commands["cd"] = Command_cd


class Command_rm(HoneyPotCommand):
    """
    rm command
    """

    def help(self) -> None:
        self.write(
            """Usage: rm [OPTION]... [FILE]...
Remove (unlink) the FILE(s).

 -f, --force           ignore nonexistent files and arguments, never prompt
 -i                    prompt before every removal
 -I                    prompt once before removing more than three files, or
                         when removing recursively; less intrusive than -i,
                         while still giving protection against most mistakes
      --interactive[=WHEN]  prompt according to WHEN: never, once (-I), or
                         always (-i); without WHEN, prompt always
      --one-file-system  when removing a hierarchy recursively, skip any
                         directory that is on a file system different from
                         that of the corresponding command line argument
      --no-preserve-root  do not treat '/' specially
      --preserve-root   do not remove '/' (default)
 -r, -R, --recursive   remove directories and their contents recursively
 -d, --dir             remove empty directories
 -v, --verbose         explain what is being done
     --help     display this help and exit
     --version  output version information and exit

By default, rm does not remove directories.  Use the --recursive (-r or -R)
option to remove each listed directory, too, along with all of its contents.

To remove a file whose name starts with a '-', for example '-foo',
use one of these commands:
 rm -- -foo

 rm ./-foo

Note that if you use rm to remove a file, it might be possible to recover
some of its contents, given sufficient expertise and/or time.  For greater
assurance that the contents are truly unrecoverable, consider using shred.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/rm>
or available locally via: info '(coreutils) rm invocation'\n"""
        )

    def paramError(self) -> None:
        self.errorWrite("Try 'rm --help' for more information\n")

    def call(self) -> None:
        recursive = False
        force = False
        verbose = False
        if not self.args:
            self.errorWrite("rm: missing operand\n")
            self.paramError()
            return

        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "rTfvh", ["help", "recursive", "force", "verbose"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"rm: invalid option -- '{err.opt}'\n")
            self.paramError()
            self.exit()
            return

        for o, _a in optlist:
            if o in ("--recursive", "-r", "-R"):
                recursive = True
            elif o in ("--force", "-f"):
                force = True
            elif o in ("--verbose", "-v"):
                verbose = True
            elif o in ("--help", "-h"):
                self.help()
                return

        for f in args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                # verify path to file exists
                dir = self.fs.get_path("/".join(pname.split("/")[:-1]))
                # verify that the file itself exists
                self.fs.get_path(pname)
            except (IndexError, fs.FileNotFound):
                if not force:
                    self.errorWrite(
                        f"rm: cannot remove `{f}': No such file or directory\n"
                    )
                continue
            basename = pname.split("/")[-1]
            for i in dir[:]:
                if i[fs.A_NAME] == basename:
                    if i[fs.A_TYPE] == fs.T_DIR and not recursive:
                        self.errorWrite(
                            f"rm: cannot remove `{i[fs.A_NAME]}': Is a directory\n"
                        )
                    else:
                        dir.remove(i)
                        if verbose:
                            if i[fs.A_TYPE] == fs.T_DIR:
                                self.write(f"removed directory '{i[fs.A_NAME]}'\n")
                            else:
                                self.write(f"removed '{i[fs.A_NAME]}'\n")


commands["/bin/rm"] = Command_rm
commands["rm"] = Command_rm


class Command_cp(HoneyPotCommand):
    """
    cp command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("cp: missing file operand\n")
            self.errorWrite("Try `cp --help' for more information.\n")
            return
        try:
            optlist, args = getopt.gnu_getopt(self.args, "-abdfiHlLPpRrsStTuvx")
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            return
        recursive = False
        for opt in optlist:
            if opt[0] in ("-r", "-a", "-R"):
                recursive = True

        def resolv(pname: str) -> str:
            rsv: str = self.fs.resolve_path(pname, self.protocol.cwd)
            return rsv

        if len(args) < 2:
            self.errorWrite(
                f"cp: missing destination file operand after `{self.args[0]}'\n"
            )
            self.errorWrite("Try `cp --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite(f"cp: target `{dest}' is not a directory\n")
            return

        if dest[-1] == "/" and not self.fs.exists(resolv(dest)) and not recursive:
            self.errorWrite(
                f"cp: cannot create regular file `{dest}': Is a directory\n"
            )
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite(
                    "cp: cannot create regular file "
                    + f"`{dest}': No such file or directory\n"
                )
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(f"cp: cannot stat `{src}': No such file or directory\n")
                continue
            if not recursive and self.fs.isdir(resolv(src)):
                self.errorWrite(f"cp: omitting directory `{src}'\n")
                continue
            s = copy.deepcopy(self.fs.getfile(resolv(src)))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest.rstrip("/"))
            if outfile in [x[fs.A_NAME] for x in dir]:
                dir.remove(next(x for x in dir if x[fs.A_NAME] == outfile))
            s[fs.A_NAME] = outfile
            dir.append(s)


commands["/bin/cp"] = Command_cp
commands["cp"] = Command_cp


class Command_mv(HoneyPotCommand):
    """
    mv command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("mv: missing file operand\n")
            self.errorWrite("Try `mv --help' for more information.\n")
            return

        try:
            optlist, args = getopt.gnu_getopt(self.args, "-bfiStTuv")
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            return

        def resolv(pname: str) -> str:
            rsv: str = self.fs.resolve_path(pname, self.protocol.cwd)
            return rsv

        if len(args) < 2:
            self.errorWrite(
                f"mv: missing destination file operand after `{self.args[0]}'\n"
            )
            self.errorWrite("Try `mv --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite(f"mv: target `{dest}' is not a directory\n")
            return

        if dest[-1] == "/" and not self.fs.exists(resolv(dest)) and len(sources) != 1:
            self.errorWrite(
                f"mv: cannot create regular file `{dest}': Is a directory\n"
            )
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite(
                    "mv: cannot create regular file "
                    + f"`{dest}': No such file or directory\n"
                )
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(f"mv: cannot stat `{src}': No such file or directory\n")
                continue
            s = self.fs.getfile(resolv(src))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest)
            if dir != os.path.dirname(resolv(src)):
                s[fs.A_NAME] = outfile
                dir.append(s)
                sdir = self.fs.get_path(os.path.dirname(resolv(src)))
                sdir.remove(s)
            else:
                s[fs.A_NAME] = outfile


commands["/bin/mv"] = Command_mv
commands["mv"] = Command_mv


class Command_mkdir(HoneyPotCommand):
    """
    mkdir command with persistent fs.pickle update.
    """

    def call(self) -> None:
        """
        Process the mkdir command and persist directories to fs.pickle.
        """
        for f in self.args:
            # Resolve the full path of the directory
            pname = self.fs.resolve_path(f, self.protocol.cwd)

            # Check if the directory already exists
            if self.fs.exists(pname):
                self.errorWrite(f"mkdir: cannot create directory `{f}': File exists\n")
                continue  # Skip to the next directory instead of stopping

            try:
                log.msg(f"DEBUG: Attempting to create directory '{pname}' with user_created=True.")

                # Create the directory in the in-memory filesystem
                self.fs.mkdir(
                    pname,
                    self.protocol.user.uid,
                    self.protocol.user.gid,
                    4096,
                    16877,
                    user_created=True
                )

                # Log the directory structure after creation
                parent_dir = self.fs.get_path(os.path.dirname(pname))
                log.msg(f"DEBUG: Parent directory contents after mkdir: {parent_dir}")

            except fs.FileNotFound:
                self.errorWrite(
                    f"mkdir: cannot create directory `{f}': No such file or directory\n"
                )
                continue

            except Exception as e:
                log.msg(f"ERROR: Failed to create directory '{pname}': {e}")
                self.errorWrite(f"mkdir: cannot create directory `{f}': {e}\n")
                continue

    def persist_directory(self, pname: str, user_created: bool = False) -> None:
        """
        Add the new directory to the fs.pickle file with the user_created flag.
        """
        pickle_file = CowrieConfig.get("shell", "filesystem")  # Dynamic path
        try:
            # Load the current fs.pickle
            with open(pickle_file, 'rb') as f:
                fs_data = pickle.load(f)
                log.msg(f"DEBUG: fs.pickle contents after loading: {fs_data}")

            # Append the new directory entry with user_created flag
            fs_data.append([
                pname,                      # Path
                1,                          # Directory flag (1 means it's a directory)
                self.protocol.user.uid,     # User ID of the creator
                self.protocol.user.gid,     # Group ID of the creator
                4096,                       # Size
                16877,                      # Mode (permissions)
                time.time(),                # Creation time
                [],                         # Empty contents
                None,                       # No target (not a symlink)
                None,                       # No realfile
                user_created                # Flag indicating if it's user-created
            ])
            log.msg(f"DEBUG: Appended directory '{pname}' to fs.pickle with user_created={user_created}.")

            # Save the updated fs.pickle
            with open(pickle_file, 'wb') as f:
                pickle.dump(fs_data, f)
                log.msg(f"DEBUG: Loaded fs.pickle data: {fs_data}")

            log.msg(f"DEBUG: Directory '{pname}' persisted to fs.pickle.")

        except Exception as e:
            log.err(f"ERROR: Failed to persist directory '{pname}' to fs.pickle: {e}")
            raise


# Register the command in the commands dictionary
commands["/bin/mkdir"] = Command_mkdir
commands["mkdir"] = Command_mkdir


class Command_rmdir(HoneyPotCommand):
    """
    rmdir command with persistent fs.pickle update for user-created directories.
    """

    def call(self) -> None:
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                # Check if directory is empty
                if len(self.fs.get_path(pname)):
                    self.errorWrite(
                        f"rmdir: failed to remove `{f}': Directory not empty\n"
                    )
                    continue

                # Get the parent directory
                dir = self.fs.get_path("/".join(pname.split("/")[:-1]))
            except (IndexError, fs.FileNotFound):
                dir = None

            fname = os.path.basename(f)
            if not dir or fname not in [x[fs.A_NAME] for x in dir]:
                self.errorWrite(
                    f"rmdir: failed to remove `{f}': No such file or directory\n"
                )
                continue

            for i in dir[:]:
                if i[fs.A_NAME] == fname:
                    if i[fs.A_TYPE] != fs.T_DIR:
                        self.errorWrite(
                            f"rmdir: failed to remove '{f}': Not a directory\n"
                        )
                        return

                    # Remove the directory from the in-memory filesystem
                    dir.remove(i)

                    # Persist changes to fs.pickle for user-created directories
                    if len(i) > 9 and i[-1]:  # Check if it's marked as user-created
                        self.persist_removal(pname)

                    log.msg(f"DEBUG [command_rmdir]: Removed user-created directory '{pname}'")
                    break

    def persist_removal(self, pname: str) -> None:
        """
        Remove the directory from fs.pickle for user-created directories.
        """
        pickle_file = CowrieConfig.get("shell", "filesystem")
        try:
            # Load the current fs.pickle
            with open(pickle_file, "rb") as f:
                fs_data = pickle.load(f)

            # Normalize pname for consistent comparison
            normalized_pname = normpath(pname.lstrip("/"))
            log.msg(f"DEBUG: Normalized pname for comparison: {normalized_pname}")

            def log_and_filter(entry, pname, normalized_pname):
                """
                Log the entry and determine if it should be included in the filtered data.
                """
                log.msg(f"DEBUG [persist_removal]: Processing entry: {entry}")
                if not isinstance(entry, list):
                    log.msg(f"DEBUG [persist_removal]: Entry is not a list: {entry}")
                    return False
                if not is_valid_entry(entry):
                    log.msg(f"DEBUG [persist_removal]: Entry is not valid: {entry}")
                    return False
                if len(entry) == 10 or (len(entry) == 11 and entry[-1] is not True) or normpath(entry[0]) != normalized_pname:
                    log.msg(f"DEBUG [persist_removal]: Entry included: {entry}")
                    return True
                log.msg(f"DEBUG [persist_removal]: Entry excluded: {entry}")
                return False

            # Use the helper function in the list comprehension
            filtered_data = [
                entry for entry in fs_data
                if log_and_filter(entry, pname, normalized_pname)
            ]

            log.msg(f"DEBUG: Filtered fs.pickle entries for removal of '{normalized_pname}': {filtered_data}")

            if not filtered_data:
                log.err("ERROR: Resulting fs.pickle data is empty. Aborting persistence.")
                return

            # Save the updated fs.pickle
            with open(pickle_file, "wb") as f:
                # Uncomment the following line to enable persistence after testing
                # pickle.dump(filtered_data, f)
                log.msg(f"DEBUG [pickle dump]: Successfully persisted updated fs.pickle after removal of '{normalized_pname}'")

        except Exception as e:
            log.err(f"ERROR [persist_removal]: Failed to remove directory '{pname}' from fs.pickle: {e}")



commands["/bin/rmdir"] = Command_rmdir
commands["rmdir"] = Command_rmdir


class Command_pwd(HoneyPotCommand):
    """
    pwd command
    """

    def call(self) -> None:
        self.write(self.protocol.cwd + "\n")


commands["/bin/pwd"] = Command_pwd
commands["pwd"] = Command_pwd


class Command_touch(HoneyPotCommand):
    """
    touch command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("touch: missing file operand\n")
            self.errorWrite("Try `touch --help' for more information.\n")
            return
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            if not self.fs.exists(os.path.dirname(pname)):
                self.errorWrite(
                    f"touch: cannot touch `{pname}`: No such file or directory\n"
                )
                return
            if self.fs.exists(pname):
                # FIXME: modify the timestamp here
                continue
            # can't touch in special directories
            if any([pname.startswith(_p) for _p in fs.SPECIAL_PATHS]):
                self.errorWrite(f"touch: cannot touch `{pname}`: Permission denied\n")
                return

            self.fs.mkfile(
                pname, self.protocol.user.uid, self.protocol.user.gid, 0, 33188
            )


commands["/bin/touch"] = Command_touch
commands["touch"] = Command_touch
commands[">"] = Command_touch
