#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo, 2024 James Brine
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or 
# without modification, are permitted provided that the 
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT 
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.

import time, uuid, logging, argparse
from twisted.python import filepath
from twisted.protocols.ftp import FTPFactory, FTPRealm, FTP
from twisted.cred.portal import Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.internet import reactor, ssl
from elasticsearch import Elasticsearch

# Argument parsing
parser = argparse.ArgumentParser(description='FTP Honeypot')
parser.add_argument('--log', choices=['screen', 'file', 'elasticsearch'], default='screen', help='Logging type')
parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
args = parser.parse_args()

# Configure logging
log_level = logging.DEBUG if args.verbose else logging.INFO
logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

if args.log == 'file':
    file_handler = logging.FileHandler('honeypot_output.txt')
    logger.addHandler(file_handler)
elif args.log == 'elasticsearch':
    es_host = '127.0.0.1'
    es_port = 9200
    es = Elasticsearch([{'host': es_host, 'port': es_port}])
class FTPConfig:
    def __init__(self):
        self.version = '0.1.0'
        self.appname = 'honeypot_ftp'
        self.port = 2121
        self.sslport = 990
        self.pubdir = 'pub/'
        self.passwdfile = 'passwd'
        self.sslcertprivate = 'keys/smtp.private.key'
        self.sslcertpublic = 'keys/smtp.public.key'
        self.enabled_handlers = {
            'elasticsearch': True, 
            'screen': True,
            'file': True
        }
        self.elasticsearch = {
            'host': '127.0.0.1', 
            'port': 9200, 
            'index': 'honeypot'
        }
        self.filename = 'honeypot_output.txt'

config = FTPConfig()

class MyFTPRealm(FTPRealm):
    def __init__(self, dir):
        self.userHome = filepath.FilePath(dir)

    def getHomeDirectory(self, avatarId):
        return self.userHome

class SimpleFtpProtocol(FTP):
    def __init__(self):
        super().__init__()
        self.session = str(uuid.uuid1())
        self.myownhost = None

    def connectionMade(self):
        self.__logInfo('connected', '', True)
        super().connectionMade()

    def connectionLost(self, reason):
        self.__logInfo('disconnected', '', True)
        super().connectionLost(reason)

    def lineReceived(self, line):
        self.__logInfo('command', line, True)
        super().lineReceived(line)

    def ftp_STOR(self, path):
        self.sendLine('125 Data connection already open, starting transfer')
        self.sendLine('226 Transfer Complete.')

    def ftp_DELE(self, path):
        self.sendLine('250 Requested File Action Completed OK')

    def ftp_RNFR(self, fromName):
        self.sendLine('350 Requested file action pending further information.')

    def ftp_RNTO(self, toName):
        self.sendLine('250 Requested File Action Completed OK')

    def ftp_MKD(self, path):
        self.sendLine('257 Folder created')

    def ftp_RMD(self, path):
        self.sendLine('250 Requested File Action Completed OK')

    def __logInfo(self, type, command, successful):
        try:
            self.myownhost = self.transport.getHost()
        except AttributeError:
            pass

        data = {
            'module': 'FTP', 
            '@timestamp': int(time.time() * 1000),
            'sourceIPv4Address': str(self.transport.getPeer().host), 
            'sourceTransportPort': self.transport.getPeer().port,
            'type': type,
            'command': command, 
            'success': successful, 
            'session': self.session
        }
        if self.myownhost:
            data['destinationIPv4Address'] = str(self.myownhost.host)
            data['destinationTransportPort'] = self.myownhost.port
        if args.log == 'screen' or args.log == 'file':
            logger.info(f"FTP Event: {data}")
        elif args.log == 'elasticsearch':
            es.index(index="honeypot", doc_type="event", body=data)

try:
    factory = FTPFactory(
        Portal(MyFTPRealm(config.pubdir)), 
        [FilePasswordDB(config.passwdfile)]
    )
    factory.protocol = SimpleFtpProtocol
    reactor.listenTCP(config.port, factory)
    if args.log == 'elasticsearch':
        reactor.listenSSL(
            config.sslport, 
            factory, 
            ssl.DefaultOpenSSLContextFactory(
                config.sslcertprivate, 
                config.sslcertpublic
            ))
    logger.info(f'Server listening on Port {config.port} (Plain) and on {config.sslport} (SSL).')
    reactor.run()
except Exception as e:
    logger.error(str(e))
    exit(-1)

logger.info('Server shutdown.')
