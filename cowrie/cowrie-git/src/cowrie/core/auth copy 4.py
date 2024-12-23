# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains authentication code
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from os import path
from random import randint
from typing import Any
from re import Pattern
import uuid
from datetime import datetime

import mysql.connector
from mysql.connector import Error
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell.protocol import HoneyPotBaseProtocol


_USERDB_DEFAULTS: list[str] = [
    "root:x:!root",
    "root:x:!123456",
    "root:x:!/honeypot/i",
    "root:x:*",
    "phil:x:*",
    "phil:x:fout",
]

class UserDB:
    """
    By Walter de Jong <walter@sara.nl>
    """

    def __init__(self) -> None:
        self.userdb: dict[
            tuple[Pattern[bytes] | bytes, Pattern[bytes] | bytes], bool
        ] = OrderedDict()
        self.db = self.connect_to_db()
        self.load()

    def connect_to_db(self):
        try:
            connection = mysql.connector.connect(
                host="cowrie-git-mysql-1",
                user="cowrie",
                password="yourpassword",
                database="cowrie"
            )
            if connection.is_connected():
                log.msg("Connected to MySQL database")
            return connection
        except Error as e:
            log.msg(f"MySQL connection error: {e}")
            return None

    def close_db(self):
        if self.db and self.db.is_connected():
            self.db.close()
            log.msg("MySQL connection closed.")

    def load(self) -> None:
        """
        Load the user db
        """
        dblines: list[str]

        userdb_path = "{}/userdb.txt".format(CowrieConfig.get("honeypot", "etc_path"))

        log.msg(f"Attempting to read user database from: {userdb_path}")

        try:
            with open(userdb_path, encoding="ascii") as db:
                dblines = db.readlines()
        except OSError as e:
            log.msg(f"Could not read {userdb_path}, error: {e}")
            dblines = _USERDB_DEFAULTS

        for user in dblines:
            if not user.startswith("#"):
                try:
                    login = user.split(":")[0].encode("utf8")
                    password = user.split(":")[2].strip().encode("utf8")
                except IndexError:
                    continue
                else:
                    self.adduser(login, password)

    def checklogin(
        self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0", protocol=None
    ) -> bool:
        for credentials, policy in self.userdb.items():
            login, passwd = credentials

            if self.match_rule(login, thelogin) and self.match_rule(passwd, thepasswd):
                # If login is successful, log it to the database
                self.log_login_attempt(thelogin.decode("utf8"), thepasswd.decode("utf8"), src_ip, True)
                self.replay_commands(thelogin.decode("utf8"), thepasswd.decode("utf8"), src_ip)
                self.replay_directories(thelogin.decode("utf8"), thepasswd.decode("utf8"), src_ip, protocol)
                return True  # Successful login
        self.log_login_attempt(thelogin.decode("utf8"), thepasswd.decode("utf8"), src_ip, False)
        return False  # Failed login

    def log_login_attempt(self, username: str, password: str, ip: str, success: bool) -> None:
        """
        Log login attempts to the database.
        """
        session_id = str(uuid.uuid4()).replace("-", "")  # Generate a new session ID
        timestamp = datetime.now()

        query = """
        INSERT INTO auth (session, success, username, password, ip, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (session_id, int(success), username, password, ip, timestamp)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            self.db.commit()
            cursor.close()
            log.msg(f"Login attempt logged for {username} at IP {ip} with success: {success}")
        except Error as e:
            log.msg(f"MySQL error during login logging: {e}")

    def replay_commands(self, username: str, password: str, ip: str) -> None:
        """
        Replay previously executed commands for returning attackers.
        """
        query = """
            SELECT DISTINCT i.input, i.timestamp
            FROM auth a
            INNER JOIN input i ON i.session = a.session
            INNER JOIN sessions s ON s.id = a.session
            WHERE a.success = 1 AND i.success = 1 
            AND a.username = %s AND a.password = %s 
            AND s.ip = %s
            AND i.input NOT LIKE '%ping%' 
            AND i.input NOT LIKE '%exit%' 
            AND i.input NOT LIKE '%ls%' 
            AND i.input NOT LIKE '%curl%' 
            AND i.input NOT LIKE '%wget%'
            ORDER BY i.timestamp ASC;
        """
        params = (username, password, ip)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            past_commands = cursor.fetchall()
            cursor.close()

            for command in past_commands:
                log.msg(f"Replaying command for {username}@{ip}: {command[0]}")
        except Error as e:
            log.msg(f"MySQL error during command replay: {e}")

    def replay_directories(self, username: str, password: str, ip: str, protocol) -> None:
        """
        Replay directory creation for a returning user.
        """
        query = """
            SELECT DISTINCT i.input, i.timestamp
            FROM auth a
            INNER JOIN input i ON i.session = a.session
            INNER JOIN sessions s ON s.id = a.session
            WHERE a.success = 1 AND i.success = 1 
            AND a.username = %s AND a.password = %s
            AND s.ip = %s
            AND i.input LIKE 'mkdir%'
            ORDER BY i.timestamp ASC;
        """

        params = (username, password, ip)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            past_directories = cursor.fetchall()
            cursor.close()

            for command in past_directories:
                directory = command[0].split()[1]  # Extract directory path
                log.msg(f"Recreating directory for {username}@{ip}: {command[0]}")
                if hasattr(protocol, "call_command"):
                    protocol.call_command(protocol.pp, HoneyPotBaseProtocol, "mkdir", directory)
                else:
                    log.msg(f"Protocol missing 'call_command', cannot create {directory}")
        except Error as e:
            log.msg(f"MySQL error during directory replay: {e}")

    def match_rule(self, rule: bytes | Pattern[bytes], data: bytes) -> bool:
        if isinstance(rule, bytes):
            return rule in [b"*", data]
        return bool(rule.search(data))

    def re_or_bytes(self, rule: bytes) -> Pattern[bytes] | bytes:
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is
        """
        res = re.match(rb"/(.+)/(i)?$", rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)
        return rule

    def adduser(self, login: bytes, passwd: bytes) -> None:
        """
        All arguments are bytes
        """
        user = self.re_or_bytes(login)

        if passwd[0] == ord("!"):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        p = self.re_or_bytes(passwd)
        self.userdb[(user, p)] = policy

