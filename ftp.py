#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Alexander Bredo
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


'''
TODO:
 - Implement new mode for persisting data AND scan for malware.
'''

import time, uuid
from twisted.python import filepath
from twisted.protocols.ftp import FTPFactory, FTPRealm, FTP
from twisted.cred.portal import Portal
from twisted.cred.checkers import FilePasswordDB
from twisted.internet import reactor, ssl

from base.applog import *
from base.appconfig import Configuration
from handler.manager import HandlerManager

class FTPConfig(Configuration):
	def setup(self, *args, **kwargs): # Defaults: 
		self.__version = '0.1.0'
		self.__appname = 'honeypot_ftp'
		self.port=21
		self.sslport=990
		self.pubdir='pub/'
		self.passwdfile='passwd'
		self.sslcertprivate='keys/smtp.private.key'
		self.sslcertpublic='keys/smtp.public.key'
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
handler = HandlerManager(config)

class MyFTPRealm(FTPRealm):
	def __init__(self, dir):
		self.userHome = filepath.FilePath(dir)

	def getHomeDirectory(self, avatarId):
		return self.userHome # Hack: Igmore Users Directory

class SimpleFtpProtocol(FTP):
	def __init__(self):
		self.session = str(uuid.uuid1()) # Now Dirty. Stateful. Multiple concurrent sessions not possible. (TODO: Memorise Stateful Data per Socket)
		self.myownhost = None

	def connectionMade(self):
		self.__logInfo('connected', '', True)
		FTP.connectionMade(self)

	def connectionLost(self, reason):
		self.__logInfo('disconnected', '', True)
		FTP.connectionLost(self, reason)

	def lineReceived(self, line):
		self.__logInfo('command', line, True)
		FTP.lineReceived(self, line)

	# BEGINN HACKS: Do not write anything to disk (Remove Functionality)

	def ftp_STOR(self, path):
		FTP.sendLine(self, '125 Data connection already open, starting transfer')
		FTP.sendLine(self, '226 Transfer Complete.')

	def ftp_DELE(self, path):
		FTP.sendLine(self, '250 Requested File Action Completed OK')

	def ftp_RNFR(self, fromName):
		FTP.sendLine(self, '350 Requested file action pending further information.')

	def ftp_RNTO(self, toName):
		FTP.sendLine(self, '250 Requested File Action Completed OK')

	def ftp_MKD(self, path):
		FTP.sendLine(self, '257 Folder created')

	def ftp_RMD(self, path):
		FTP.sendLine(self, '250 Requested File Action Completed OK')
		
#	def sendLine(self, msg):
#		print " --> " + msg
#		return FTP.sendLine(self, msg)

	# END HACKS

	def __logInfo(self, type, command, successful):
		try: # Hack: On Connection-Close socket unavailable. remember old ip.
			self.myownhost = self.transport.getHost()
		except AttributeError:
			pass # nothing

		data = {
			'module': 'FTP', 
			'@timestamp': int(time.time() * 1000), # in milliseconds
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

		handler.handle(data)

try:
	factory = FTPFactory(
		Portal(MyFTPRealm(config.pubdir)), 
		[FilePasswordDB(config.passwdfile)]
	)
	factory.protocol = SimpleFtpProtocol
	reactor.listenTCP(config.port, factory)
	reactor.listenSSL(
		config.sslport, 
		factory, 
		ssl.DefaultOpenSSLContextFactory(
			config.sslcertprivate, 
			config.sslcertpublic
	))
	log.info('Server listening on Port %s (Plain) and on %s (SSL).' % (config.port, config.sslport))
	reactor.run()
except Exception as e:
	log.error(str(e));
	exit(-1)
log.info('Server shutdown.')