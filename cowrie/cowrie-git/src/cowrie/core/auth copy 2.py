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

import mysql.connector
from mysql.connector import Error
from twisted.python import log

from cowrie.core.config import CowrieConfig

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
                host="mysql-cowrie",
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
        self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0"
    ) -> bool:
        for credentials, policy in self.userdb.items():
            login, passwd = credentials

            if self.match_rule(login, thelogin) and self.match_rule(passwd, thepasswd):
                # If login is successful, log it to the database and check for replay
                if policy:
                    self.log_and_check_replay(thelogin.decode("utf8"), thepasswd.decode("utf8"), src_ip)
                return policy
        return False

    def log_and_check_replay(self, username: str, password: str, ip: str) -> None:
        """
        Log login attempts to the database and check if this login is a repeat.
        """
        query = """
            SELECT COUNT(*)
            FROM sessions
            WHERE ip = %s AND username = %s AND password = %s
        """
        params = (ip, username, password)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            count = cursor.fetchone()[0]
            cursor.close()

            # If count is greater than 0, replay commands
            if count > 0:
                self.replay_commands(username, password, ip)
            else:
                # Log this as a new session if no replay is needed
                self.log_session(username, password, ip)
        except Error as e:
            log.msg(f"MySQL error during login check: {e}")

    def replay_commands(self, username: str, password: str, ip: str) -> None:
        """
        Replay previously executed commands for returning attackers.
        """
        query = """
            SELECT DISTINCT i.input
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
            AND i.input NOT LIKE '%wget%';
        """
        params = (username, password, ip)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            past_commands = cursor.fetchall()
            cursor.close()

            for command in past_commands:
                self.simulate_command(command[0])  # Replace with actual command simulation method
        except Error as e:
            log.msg(f"MySQL error during command replay: {e}")

    def log_session(self, username: str, password: str, ip: str) -> None:
        """
        Log a new session in the database for first-time login.
        """
        query = "INSERT INTO sessions (username, password, ip) VALUES (%s, %s, %s)"
        params = (username, password, ip)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            self.db.commit()
            cursor.close()
            log.msg(f"Session logged for {username} at IP {ip}")
        except Error as e:
            log.msg(f"MySQL error during session logging: {e}")

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


class AuthRandom:
    """
    Alternative class that defines the checklogin() method.
    Users will be authenticated after a random number of attempts.
    """

    def __init__(self) -> None:
        # Default values
        self.mintry: int = 2
        self.maxtry: int = 5
        self.maxcache: int = 10

        # Are there auth_class parameters?
        if CowrieConfig.has_option("honeypot", "auth_class_parameters"):
            parameters: str = CowrieConfig.get("honeypot", "auth_class_parameters")
            parlist: list[str] = parameters.split(",")
            if len(parlist) == 3:
                self.mintry = int(parlist[0])
                self.maxtry = int(parlist[1])
                self.maxcache = int(parlist[2])

        if self.maxtry < self.mintry:
            self.maxtry = self.mintry + 1
            log.msg(f"maxtry < mintry, adjusting maxtry to: {self.maxtry}")

        self.uservar: dict[Any, Any] = {}
        self.uservar_file: str = "{}/auth_random.json".format(
            CowrieConfig.get("honeypot", "state_path")
        )
        self.loadvars()

    def loadvars(self) -> None:
        """
        Load user vars from json file
        """
        if path.isfile(self.uservar_file):
            with open(self.uservar_file, encoding="utf-8") as fp:
                try:
                    self.uservar = json.load(fp)
                except Exception:
                    self.uservar = {}

    def savevars(self) -> None:
        """
        Save the user vars to json file
        """
        data = self.uservar
        with open(self.uservar_file, "w", encoding="utf-8") as fp:
            json.dump(data, fp)

    def checklogin(self, thelogin: bytes, thepasswd: bytes, src_ip: str) -> bool:
        """
        Every new source IP will have to try a random number of times between
        'mintry' and 'maxtry' before succeeding to login.
        """
        auth: bool = False
        userpass: str = str(thelogin) + ":" + str(thepasswd)

        if "cache" not in self.uservar:
            self.uservar["cache"] = []
        cache = self.uservar["cache"]

        if src_ip not in self.uservar:
            self.uservar[src_ip] = {}
            ipinfo = self.uservar[src_ip]
            ipinfo["try"] = 0
            if userpass in cache:
                log.msg(f"first time for {src_ip}, found cached: {userpass}")
                ipinfo["max"] = 1
                ipinfo["user"] = str(thelogin)
                ipinfo["pw"] = str(thepasswd)
                auth = True
                self.savevars()
                return auth
            ipinfo["max"] = randint(self.mintry, self.maxtry)
            log.msg(f"first time for {src_ip}, need: {ipinfo['max']}")
        else:
            if userpass in cache:
                ipinfo = self.uservar[src_ip]
                log.msg(f"Found cached: {userpass}")
                ipinfo["max"] = 1
                ipinfo["user"] = str(thelogin)
                ipinfo["pw"] = str(thepasswd)
                auth = True
                self.savevars()
                return auth

        ipinfo = self.uservar[src_ip]
        ipinfo.setdefault("max", randint(self.mintry, self.maxtry))
        ipinfo.setdefault("try", 0)
        ipinfo.setdefault("tried", [])

        if userpass in ipinfo["tried"]:
            log.msg("already tried this combination")
            self.savevars()
            return auth

        ipinfo["try"] += 1
        attempts = ipinfo["try"]
        need = ipinfo["max"]
        log.msg(f"login attempt: {attempts}")

        if attempts < need:
            ipinfo["tried"].append(userpass)
        elif attempts == need:
            ipinfo["user"] = str(thelogin)
            ipinfo["pw"] = str(thepasswd)
            cache.append(userpass)
            if len(cache) > self.maxcache:
                cache.pop(0)
            auth = True
        elif attempts > need:
            if "user" not in ipinfo or "pw" not in ipinfo:
                log.msg("return, but username or password not set!!!")
                ipinfo["tried"].append(userpass)
                ipinfo["try"] = 1
            else:
                log.msg(
                    f"login return, expect: [{ipinfo['user']}/{ipinfo['pw']}]"
                )
                if thelogin == ipinfo["user"] and str(thepasswd) == ipinfo["pw"]:
                    auth = True
        self.savevars()
        return auth
