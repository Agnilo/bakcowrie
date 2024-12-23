# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from zope.interface import implementer

from twisted.conch.interfaces import ISession
from twisted.conch.ssh import session
from twisted.python import log

from cowrie.insults import insults
from cowrie.shell import protocol
from cowrie.shell.command import CommandHistory
from cowrie.shell import fs


@implementer(ISession)
class SSHSessionForCowrieUser:
    def __init__(self, avatar, reactor=None):
        """
        Construct an C{SSHSessionForCowrieUser}.

        @param avatar: The L{CowrieUser} for whom this is an SSH session.
        @param reactor: An L{IReactorProcess} used to handle shell and exec
            requests. Uses the default reactor if None.
        """
        self.protocol = None
        self.avatar = avatar
        self.server = avatar.server
        self.uid = avatar.uid
        self.gid = avatar.gid
        self.username = avatar.username
        self.environ = {
            "LOGNAME": self.username,
            "SHELL": "/bin/bash",
            "USER": self.username,
            "HOME": self.avatar.home,
            "TMOUT": "1800",
            "UID": str(self.uid),
        }
        if self.uid == 0:
            self.environ["PATH"] = (
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            )
        else:
            self.environ["PATH"] = (
                "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
            )

        # Initialize the file system
        self.server.initFileSystem(self.avatar.home)

        # Ensure /home exists
        home_base = "/home"
        if not self.server.fs.exists(home_base):
            self.server.fs.mkdir(home_base, 0, 0, 4096, 0o755)
            log.msg(f"DEBUG: Created directory '{home_base}'")

        # Ensure the user's home directory exists
        if self.avatar.temporary:
            if not self.server.fs.exists(self.avatar.home):
                self.server.fs.mkdir(self.avatar.home, self.uid, self.gid, 4096, 0o755)
                log.msg(f"DEBUG: Created home directory '{self.avatar.home}' for user '{self.username}'")

        # Initialize command history for the user
        self.command_history = CommandHistory()

    # New lineReceived method
    def lineReceived(self, line: str):
        """ Handle received lines from the shell """
        if line == '\x1b[A':  # Up arrow key (key code for up arrow is \x1b[A)
            prev_command = self.command_history.get_previous()
            if prev_command:
                self.write(f"\r{prev_command}")
                self.setLineBuffer(prev_command)
            else:
                self.write("\r")  # If no previous command, just clear the line
        elif line == '\x1b[B':  # Down arrow key (key code for down arrow is \x1b[B)
            next_command = self.command_history.get_next()
            if next_command:
                self.write(f"\r{next_command}")
                self.setLineBuffer(next_command)
            else:
                self.write("\r")  # If no next command, just clear the line
        else:
            # Handle normal command execution
            super().lineReceived(line)

    def write(self, data: str):
        """ Writes output to the user """
        self.protocol.write(data.encode("utf-8"))

    def setLineBuffer(self, line: str):
        """ Update the input buffer with the new command """
        self.protocol.setLineBuffer(line)

    def openShell(self, processprotocol):
        # Set up the interactive protocol with logging
        self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotInteractiveProtocol, self
        )   
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))

        # Safely obtain the session ID based on the peer's IP address
        peer = self.protocol.transport.getPeer()
    
        # Use `host` if available; otherwise, use the string representation of `peer`
        session_id = getattr(peer, 'host', str(peer))
    
        # Log the session ID for debugging
        log.msg(f"Session ID set to: {session_id}")
    
        # Load the command history for the current session
        self.command_history.load_history(session_id)

    def getPty(self, terminal, windowSize, attrs):
        self.environ["TERM"] = terminal.decode("utf-8")
        log.msg(
            eventid="cowrie.client.size",
            width=windowSize[1],
            height=windowSize[0],
            format="Terminal Size: %(width)s %(height)s",
        )
        self.windowSize = windowSize

    def execCommand(self, processprotocol, cmd):
        self.protocol = insults.LoggingServerProtocol(
            protocol.HoneyPotExecProtocol, self, cmd
        )
        self.protocol.makeConnection(processprotocol)
        processprotocol.makeConnection(session.wrapProtocol(self.protocol))

    def closed(self) -> None:
        """
        this is reliably called on both logout and disconnect
        we notify the protocol here we lost the connection
        """
        if self.protocol:
            self.protocol.connectionLost("disconnected")
            self.protocol = None

    def eofReceived(self) -> None:
        if self.protocol:
            self.protocol.eofReceived()

    def windowChanged(self, windowSize):
        self.windowSize = windowSize
