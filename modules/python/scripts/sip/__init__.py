#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (c) 2010 Tobias Wulff (twu200 at gmail)
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* 
#*             contact nepenthesdev@gmail.com  
#*
#*******************************************************************************/
#*
#*
#* Parts of the SIP response codes and a lot of SIP message parsing are taken
#* from the Twisted Core: http://twistedmatrix.com/trac/wiki/TwistedProjects
#*
#* The hash calculation for SIP authentication has been copied from SIPvicious
#* Sipvicious (c) Sandro Gaucci: http://code.google.com/p/sipvicious
#*******************************************************************************


import logging
import time
import random
import hashlib
import os
import errno
import datetime
import tempfile

from dionaea.sip import rfc3261
from dionaea.sip import rfc4566

from dionaea.core import connection, ihandler, g_dionaea, incident
from dionaea import pyev

def int2bytes(value):
	"""
	Convert integer to bytes
	"""
	return bytes(str(value), "utf-8")


g_default_loop = pyev.default_loop()

logger = logging.getLogger('sip')
logger.setLevel(logging.DEBUG)

# Shortcut to sip config
g_sipconfig = g_dionaea.config()['modules']['python']['sip']

_SipSession_sustain_timeout = 20
_SipCall_sustain_timeout = 20

# Make "yes"/"no" from config file into boolean value
if g_sipconfig['use_authentication'].lower() == 'no':
	g_sipconfig['use_authentication'] = False
else:
	g_sipconfig['use_authentication'] = True

if g_sipconfig['record_rtp'].lower() == 'no':
	g_sipconfig['record_rtp'] = False
else:
	g_sipconfig['record_rtp'] = True

# Shortcut hashing function
def hash(s):
	return hashlib.md5(s.encode('utf-8')).hexdigest()

#############
# SIP globals
#############

TRYING                      = '100'
RINGING                     = '180'
CALL_FWD                    = '181'
QUEUED                      = '182'
PROGRESS                    = '183'
OK                          = '200'
ACCEPTED                    = '202'
MULTI_CHOICES               = '300'
MOVED_PERMANENTLY           = '301'
MOVED_TEMPORARILY           = '302'
SEE_OTHER					= '303'
USE_PROXY                   = '305'
ALT_SERVICE                 = '380'
BAD_REQUEST                 = '400'
UNAUTHORIZED                = '401'
PAYMENT_REQUIRED            = '402'
FORBIDDEN                   = '403'
NOT_FOUND                   = '404'
NOT_ALLOWED                 = '405'
NOT_ACCEPTABLE              = '406'
PROXY_AUTH_REQUIRED         = '407'
REQUEST_TIMEOUT             = '408'
CONFLICT                    = '409'
GONE                        = '410'
LENGTH_REQUIRED             = '411'
ENTITY_TOO_LARGE            = '413'
URI_TOO_LARGE               = '414'
UNSUPPORTED_MEDIA           = '415'
UNSUPPORTED_URI				= '416'
BAD_EXTENSION               = '420'
EXTENSION_REQUIRED			= '421'
INTERVAL_TOO_BRIEF			= '423'
NOT_AVAILABLE               = '480'
NO_TRANSACTION              = '481'
LOOP                        = '482'
TOO_MANY_HOPS               = '483'
ADDRESS_INCOMPLETE          = '484'
AMBIGUOUS                   = '485'
BUSY_HERE                   = '486'
CANCELLED                   = '487'
NOT_ACCEPTABLE_HERE         = '488'
REQUEST_PENDING				= '491'
UNDECIPHERABLE				= '493'
INTERNAL_ERROR              = '500'
NOT_IMPLEMENTED             = '501'
BAD_GATEWAY                 = '502'
UNAVAILABLE                 = '503'
GATEWAY_TIMEOUT             = '504'
SIP_VERSION_NOT_SUPPORTED   = '505'
MESSAGE_TOO_LARGE			= '513'
BUSY_EVERYWHERE             = '600'
DECLINE                     = '603'
DOES_NOT_EXIST              = '604'
NOT_ACCEPTABLE_6xx          = '606'

# SIP Responses from SIP Demystified by Gonzalo Camarillo
RESPONSE = { 
	# 1xx
	TRYING:                     '100 Trying',
	RINGING:                    '180 Ringing',
	CALL_FWD:                   '181 Call is being forwarded',
	QUEUED:                     '182 Queued',
	PROGRESS:                   '183 Session progress',

	# 2xx
	OK:                         '200 OK',
	ACCEPTED:                   '202 Accepted',

	# 3xx
	MULTI_CHOICES:              '300 Multiple choices',
	MOVED_PERMANENTLY:          '301 Moved permanently',
	MOVED_TEMPORARILY:          '302 Moved temporarily',
	SEE_OTHER:					'303 See other',
	USE_PROXY:                  '305 Use proxy',
	ALT_SERVICE:                '380 Alternative service',

	# 4xx
	BAD_REQUEST:                '400 Bad request',
	UNAUTHORIZED:               '401 Unauthorized',
	PAYMENT_REQUIRED:           '402 Payment required',
	FORBIDDEN:                  '403 Forbidden',
	NOT_FOUND:                  '404 Not found',
	NOT_ALLOWED:                '405 Method not allowed',
	NOT_ACCEPTABLE:             '406 Not acceptable',
	PROXY_AUTH_REQUIRED:        '407 Proxy authentication required',
	REQUEST_TIMEOUT:            '408 Request time-out',
	CONFLICT:                   '409 Conflict',
	GONE:                       '410 Gone',
	LENGTH_REQUIRED:            '411 Length required',
	ENTITY_TOO_LARGE:           '413 Request entity too large',
	URI_TOO_LARGE:              '414 Request-URI too large',
	UNSUPPORTED_MEDIA:          '415 Unsupported media type',
	UNSUPPORTED_URI:			'416 Unsupported URI scheme',
	BAD_EXTENSION:              '420 Bad extension',
	EXTENSION_REQUIRED:			'421 Extension required',
	INTERVAL_TOO_BRIEF:			'423 Interval too brief',
	NOT_AVAILABLE:              '480 Temporarily not available',
	NO_TRANSACTION:             '481 Call leg/transaction does not exist',
	LOOP:                       '482 Loop detected',
	TOO_MANY_HOPS:              '483 Too many hops',
	ADDRESS_INCOMPLETE:         '484 Address incomplete',
	AMBIGUOUS:                  '485 Ambiguous',
	BUSY_HERE:                  '486 Busy here',
	CANCELLED:                  '487 Request cancelled',
	NOT_ACCEPTABLE_HERE:        '488 Not acceptable here',
	REQUEST_PENDING:			'491 Request pending',
	UNDECIPHERABLE:				'493 Undecipherable',

	# 5xx
	INTERNAL_ERROR:             '500 Internal server error',
	NOT_IMPLEMENTED:            '501 Not implemented',
	BAD_GATEWAY:                '502 Bad gateway',
	UNAVAILABLE:                '503 Service unavailable',
	GATEWAY_TIMEOUT:            '504 Gateway time-out',
	SIP_VERSION_NOT_SUPPORTED:  '505 SIP version not supported',
	MESSAGE_TOO_LARGE:			'513 Message too large',

	# 6xx
	BUSY_EVERYWHERE:            '600 Busy everywhere',
	DECLINE:                    '603 Decline',
	DOES_NOT_EXIST:             '604 Does not exist anywhere',
	NOT_ACCEPTABLE_6xx:         '606 Not acceptable'
}

# SIP headers have short forms
shortHeaders = {"call-id": "i",
                "contact": "m",
                "content-encoding": "e",
                "content-length": "l",
                "content-type": "c",
                "from": "f",
                "subject": "s",
                "to": "t",
                "via": "v",
				"cseq": "cseq",
				"accept": "accept",
				"user-agent": "user-agent",
				"max-forwards": "max-forwards",
				"www-authentication": "www-authentication",
				"authorization": "authorization"
                }

longHeaders = {}
for k, v in shortHeaders.items():
	longHeaders[v] = k
del k, v

class SipParsingError(Exception):
	"""Exception class for errors occuring during SIP message parsing"""

class AuthenticationError(Exception):
	"""Exception class for errors occuring during SIP authentication"""

#############
# SDP globals
#############

sessionDescriptionTypes = {
	"v": "protocol version",
	"o": "session owner",
	"s": "session name",
	"i": "session information",
	"u": "uri",
	"e": "email address",
	"p": "phone number",
	"c": "connection information",
	"b": "bandwidth information",
	"z": "time zone adjustment",
	"k": "encryption key",
	"t": "active time",
	"r": "repeat time",
	"a": "session attribute line"
}

mediaDescriptionTypes = {
	"m": "media name",
	"i": "media title",
	"c": "connection information",
	"b": "bandwidth information",
	"k": "encryption key",
	"a": "attribute line"
}

class SdpParsingError(Exception):
	"""Exception class for errors occuring during SDP message parsing"""

###################
# Parsing functions
###################

def parseSdpMessage(msg):
	"""Parses an SDP message (string), returns a tupel of dictionaries with
	{type: value} entries: (sessionDescription, mediaDescriptions)"""
	# Normalize line feed and carriage return to \n
	msg = msg.replace("\n\r", "\n")

	# Sanitize input: remove superfluous leading and trailing newlines and
	# spaces
	msg = msg.strip("\n\r\t ")

	# Split message into session description, and media description parts
	SEC_SESSION, SEC_MEDIA = range(2)
	curSection = SEC_SESSION
	sessionDescription = {}
	mediaDescriptions = []
	mediaDescriptionNumber = -1

	# Process each line individually
	if len(msg) > 0:
		lines = msg.split("\n")
		for line in lines:
			# Remove leading and trailing whitespaces from line
			line = line.strip('\n\r\t ')

			# Get first two characters of line and check for "type="
			if len(line) < 2:
				raise SdpParsingError("Line too short")
			elif line[1] != "=":
				raise SdpParsingError("Invalid SDP line")

			type = line[0]
			value = line[2:].strip("\n\r\t ")

			# Change current section if necessary
			# (session -> media -> media -> ...)
			if type == "m":
				curSection = SEC_MEDIA
				mediaDescriptionNumber += 1
				mediaDescriptions.append({})

			# Store the SDP values
			if curSection == SEC_SESSION:
				if type not in sessionDescriptionTypes:
					raise SdpParsingError(
						"Invalid session description type: " + type)
				else:
					sessionDescription[type] = value
			elif curSection == SEC_MEDIA:
				if type not in mediaDescriptionTypes:
					raise SdpParsingError(
						"Invalid media description type: " + type)
				else:
					mediaDescriptions[mediaDescriptionNumber][type] = value

	return (sessionDescription, mediaDescriptions)

def parseSipMessage(msg):
	"""Parses a SIP message (string), returns a tupel (type, firstLine, header,
	body)"""
	# Sanitize input: remove superfluous leading and trailing newlines and
	# spaces
	msg = msg.strip("\n\r\t ")

	# Split request/status line plus headers from body: we don't care about the
	# body in the SIP parser
	parts = msg.split("\n\n", 1)
	if len(parts) < 1:
		logger.warn("SIP message is too short")
		raise SipParsingError("SIP message is too short")

	msg = parts[0]

	# Python way of doing a ? b : c
	body = len(parts) == 2 and parts[1] or ''

	# Normalize line feed and carriage return to \n
	msg = msg.replace("\n\r", "\n")

	# Split lines into a list, each item containing one line
	lines = msg.split('\n')

	# Get message type (first word, smallest possible one is "ACK" or "BYE")
	sep = lines[0].find(' ')
	if sep < 3:
		raise SipParsingError("Malformed request or status line")

	msgType = lines[0][:sep]
	firstLine = lines[0][sep+1:]

	# Done with first line: delete from list of lines
	del lines[0]

	# Parse header
	headers = {}
	for i in range(len(lines)):
		# Take first line and remove from list of lines
		line = lines.pop(0)

		# Strip each line of leading and trailing whitespaces
		line = line.strip("\n\r\t ")

		# Break on empty line (end of headers)
		if len(line.strip(' ')) == 0:
			break

		# Parse header lines
		sep = line.find(':')
		if sep < 1:
			raise SipParsingError("Malformed header line (no ':')")

		# Get header identifier (word before the ':')
		identifier = line[:sep]
		identifier = identifier.lower()

		# Check for valid header
		if identifier not in shortHeaders.keys() and \
			identifier not in longHeaders.keys():
			raise SipParsingError("Unknown header type: {}".format(identifier))

		# Get long header identifier if necessary
		if identifier in longHeaders.keys():
			identifier = longHeaders[identifier]

		# Get header value (line after ':')
		value = line[sep+1:].strip(' ')

		# The Via header can occur multiple times
		if identifier == "via":
			if identifier not in headers:
				headers["via"] = [value]
			else:
				headers["via"].append(value)

		# Assign any other header value directly to the header key
		else:
			headers[identifier] = value

	# Return message type, header dictionary, and body string
	return (msgType, firstLine, headers, body)

#########
# Classes
#########

class RtpUdpStream(connection):
	"""RTP stream that can send data and writes the whole conversation to a
	file"""
	def __init__(self, localAddress, remoteAddress, port):
		connection.__init__(self, 'udp')

		# Bind to free random port for incoming RTP traffic
		self.bind(localAddress, 0)
		self.connect(remoteAddress, int(port))

		# The address and port of the remote host
		self.remote.host = remoteAddress
		self.remote.port = int(port)

		# Send byte buffer
		self.__sendBuffer = b''

		# Create a stream dump file with date and time and random ID in case of
		# flooding attacks
		global g_sipconfig
		self.__streamDumpIn = None
		dumpDate = time.strftime('%Y-%m-%d')
		dumpTime = time.strftime('%H:%M:%S')
		dumpDir = 'var/dionaea/rtp/{}/'.format(dumpDate)

		# Construct dump file name
		self.__streamDumpFileIn = dumpDir + '{t}_{h}_{p}_in.rtp'.format(
			t=dumpTime, h=self.remote.host, p=self.remote.port)

		# Report incident
		i = incident("dionaea.modules.python.sip.rtp")
		i.con = self
		i.dumpfile = self.__streamDumpFileIn
		i.report()

		logger.info("Created RTP channel on ports :{} <-> :{}".format(
			self.local.port, self.remote.port))

	def close(self):
		if self.__streamDumpIn:
			logger.debug("Closing stream dump (in)")
			self.__streamDumpIn.close()

		connection.close(self)

	def handle_timeout_idle(self):
		return True

	def handle_timeout_sustain(self):
		return True

	def handle_io_in(self, data):
		logger.debug("Incoming RTP data (length {})".format(len(data)))

		if g_sipconfig['record_rtp']:
			# Create stream dump file only if not previously failed
			if not self.__streamDumpIn and self.__streamDumpFileIn:
				self.__startRecording()

			# Write incoming data to disk
			if self.__streamDumpIn:
				self.__streamDumpIn.write(data)

		return len(data)

	def handle_io_out(self):
		logger.debug("Outdoing RTP data (length {})".format(len(data)))

		bytesSent = self.send(self.__sendBuffer)

		# Shift sending window for next send operation
		self.__sendBuffer = self.__sendBuffer[bytesSent:]

	def __startRecording(self):
		dumpDir = self.__streamDumpFileIn.rsplit('/', 1)[0]

		# Create directories if necessary
		try:
			os.mkdir(dumpDir)
		except OSError as e:
			# If directory didn't exist already, rethrow exception
			if e.errno != errno.EEXIST:
				raise e

		# Catch IO errors
		try:
			self.__streamDumpIn = open(self.__streamDumpFileIn, "wb")
		except IOError as e:
			logger.error("RtpStream: Could not open stream dump file: {}".format(e))
			self.__streamDumpIn = None
			self.__streamDumpFileIn = None
		else:
			logger.debug("Created RTP dump file")

class SipCall(connection):
	"""Usually, a new SipSession instance is created when the SIP server
	receives an INVITE message"""
	NO_SESSION, SESSION_SETUP, ACTIVE_SESSION, SESSION_TEARDOWN = range(4)

	def __init__(self, session, conInfo, rtpPort, inviteHeaders):
		logger.debug("SipCall {} session {} ".format(self, session))
		connection.__init__(self,'udp')
		# Store incoming information of the remote host

		self.__session = session
		self.__state = SipCall.SESSION_SETUP
		self.__remoteAddress = conInfo[0]
		self.__remoteSipPort = conInfo[1]
		self.__remoteRtpPort = rtpPort
		self.__callId = inviteHeaders['call-id']
		self._rtpStream = None

		self.local.host = self.__session.local.host
		self.local.port = self.__session.local.port

		self.remote.host = self.__session.remote.host
		self.remote.port = self.__session.remote.port


		# fake a connection entry
		i = incident("dionaea.connection.udp.connect")
		i.con = self
		i.report()

		# Generate static values for SIP messages
		global g_sipconfig
		self.__sipTo = inviteHeaders['from']
		self.__sipFrom = "{0} <sip:{0}@{1}>".format(
			g_sipconfig['user'], g_sipconfig['domain'])
		self.__sipVia = "SIP/2.0/UDP {}:{}".format(
			g_sipconfig['domain'], g_sipconfig['port'])
		self.__sipContact = "{0} <sip:{0}@{1}>".format(
			g_sipconfig['user'], self.__session.local.host)

		global _SipCall_sustain_timeout
		self.timers = [ pyev.Timer(5, 0, g_default_loop, self.__handle_idle_timeout), # idle
			pyev.Timer(_SipCall_sustain_timeout, 0, g_default_loop, self.__handle_sustain_timeout), # sustain
			pyev.Timer(3, 0, g_default_loop, self.__handle_invite_timeout) # invite
		]

		self.timers[1].start()
		
	def send(self, s):
		s += '\n\n'
		self.__session.send(s)

	def close(self):
		logger.debug("SipCall.close {} Session {}".format(self, self.__session))
		# remove Call from Session
		if self.__callId in self.__session._callids:
			del self.__session._callids[self.__callId]

		# close rtpStream
		if self._rtpStream != None:
			self._rtpStream.close()
			self._rtpStream = None

		# stop timers
		for t in self.timers:
			logger.debug("SipCall timer {} active {} pending {}".format(t,t.active,t.pending))
			if t.active == True or t.pending == True:
#				logger.warn("SipCall Stopping {}".format(t))
				t.stop()
		
		# close connection
		connection.close(self)
		
	def __handle_idle_timeout(self, watcher, events):
#		logger.warn("self {} IDLE TIMEOUT watcher {}".format(self, watcher))
		pass

	def __handle_sustain_timeout(self, watcher, events):
		logger.debug("SipCall.__handle_sustain_timeout self {} watcher {}".format(self, watcher))
		self.close()

	def __handle_invite_timeout(self, watcher, events):
		# Send our RTP port to the remote host as a 200 OK response to the
		# remote host's INVITE request
		logger.debug("SipCall: {} CallID {}".format(self, self.__callId))
		headers = watcher.data
		localRtpPort = self._rtpStream.local.port

		msgLines = []
		msgLines.append("SIP/2.0 " + RESPONSE[OK])
		msgLines.append("Via: " + self.__sipVia)
		msgLines.append("Max-Forwards: 70")
		msgLines.append("To: " + self.__sipTo)
		msgLines.append("From: " + self.__sipFrom)
		msgLines.append("Call-ID: {}".format(self.__callId))
		msgLines.append("CSeq: " + headers['cseq'])
		msgLines.append("Contact: " + self.__sipContact)
		msgLines.append("User-Agent: " + g_sipconfig['useragent'])
		msgLines.append("Content-Type: application/sdp")
		msgLines.append("\nv=0")
		msgLines.append("o=... 0 0 IN IP4 localhost")
		msgLines.append("t=0 0")
		msgLines.append("m=audio {} RTP/AVP 0".format(localRtpPort))
		self.send('\n'.join(msgLines))

		# Stop timer
		self.timers[2].stop()


	def handle_INVITE(self, headers):
		# Check authentication
		self.__authenticate(headers)

		# Create RTP stream instance and pass address and port of listening
		# remote RTP host
		self._rtpStream = RtpUdpStream(self.__session.local.host,
			self.__remoteAddress, self.__remoteRtpPort)
		
		i = incident("dionaea.connection.link")
		i.parent = self
		i.child = self._rtpStream
		i.report()



		# Send 180 Ringing to make honeypot appear more human-like
		msgLines = []
		msgLines.append("SIP/2.0 " + RESPONSE[RINGING])
		msgLines.append("Via: " + self.__sipVia)
		msgLines.append("Max-Forwards: 70")
		msgLines.append("To: " + self.__sipTo)
		msgLines.append("From: " + self.__sipFrom)
		msgLines.append("Call-ID: {}".format(self.__callId))
		msgLines.append("CSeq: " + headers['cseq'])
		msgLines.append("Contact: " + self.__sipContact)
		msgLines.append("User-Agent: " + g_sipconfig['useragent'])
		self.send('\n'.join(msgLines))

		# Start timer for INVITE response
		self.timers[2].data = headers
		self.timers[2].start()
		return 0

	def handle_ACK(self, headers, body):
		if self.__state != SipCall.SESSION_SETUP:
			logger.warn("ACK received but not in session setup mode")

		else:
			# Authenticate ACK
			self.__authenticate(headers)

			logger.info("SIP session established (session {})".format(
				self.__callId))

			# Set current state to active (ready for multimedia stream)
			self.__state = SipCall.ACTIVE_SESSION

			# Send 200 OK response
			msgLines = []
			msgLines.append("SIP/2.0 " + RESPONSE[OK])
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipContact)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			self.send('\n'.join(msgLines))

	def handle_CANCEL(self, headers, body):
		self.__authenticate(headers)

	def handle_BYE(self, headers, body):
		global g_sipconfig

		if self.__state != SipCall.ACTIVE_SESSION:
			logger.warn("BYE received but not in active session mode")
		else:
			self.__authenticate(headers)

			# Send OK response to other client
			msgLines = []
			msgLines.append("SIP/2.0 200 OK")
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipContact)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			self.send('\n'.join(msgLines))

			# A BYE ends the session immediately
			self.__state = SipCall.NO_SESSION
			self._rtpStream.close()
			self._rtpStream = None

	def __authenticate(self, headers):
		global g_sipconfig

		if not g_sipconfig['use_authentication']:
			logger.debug("Skipping authentication")
			return

		logger.debug("'Authorization' in SIP headers: {}".format(
			'authorization' in headers))

		def sendUnauthorized(nonce):
			msgLines = []
			msgLines.append('SIP/2.0 ' + RESPONSE[UNAUTHORIZED])
			msgLines.append("Via: " + self.__sipVia)
			msgLines.append("Max-Forwards: 70")
			msgLines.append("To: " + self.__sipTo)
			msgLines.append("From: " + self.__sipFrom)
			msgLines.append("Call-ID: {}".format(self.__callId))
			msgLines.append("CSeq: " + headers['cseq'])
			msgLines.append("Contact: " + self.__sipContact)
			msgLines.append("User-Agent: " + g_sipconfig['useragent'])
			msgLines.append('WWW-Authenticate: Digest ' + \
				'realm="{}@{}",'.format(g_sipconfig['user'],
					g_sipconfig['domain']) + \
				'nonce="{}"'.format(nonce))
			self.send('\n'.join(msgLines))

		if "authorization" not in headers:
			# Calculate new nonce for authentication based on current time
			nonce = hash("{}".format(time.time()))

			# Send 401 Unauthorized response
			sendUnauthorized(nonce)

			raise AuthenticationError("Request was unauthenticated")
		else:
			# Check against config file
			authMethod, authLine = headers['authorization'].split(' ', 1)
			if authMethod != 'Digest':
				logger.warn("Authorization method is not Digest")
				raise AuthenticationError("Method is not Digest")

			# Get Authorization header parts (a="a", b="b", c="c", ...) and put
			# them in a dictionary for easy lookup
			authLineParts = [x.strip(' \t\r\n') for x in authLine.split(',')]
			authLineDict = {}
			for x in authLineParts:
				parts = x.split('=')
				authLineDict[parts[0]] = parts[1].strip(' \n\r\t"\'')

			logger.debug("Authorization dict: {}".format(authLineDict))

			if 'nonce' not in authLineDict:
				logger.warn("Nonce missing from authorization header")
				raise AuthenticationError("Nonce missing")

			if 'response' not in authLineDict:
				logger.warn("Response missing from authorization header")
				raise AuthenticationError("Response missing")

			# The calculation of the expected response is taken from
			# Sipvicious (c) Sandro Gaucci
			realm = "{}@{}".format(g_sipconfig['user'], g_sipconfig['domain'])
			uri = "sip:" + realm
			a1 = hash("{}:{}:{}".format(
				g_sipconfig['user'], realm, g_sipconfig['secret']))
			a2 = hash("INVITE:{}".format(uri))
			expected = hash("{}:{}:{}".format(a1, authLineDict['nonce'], a2))

			logger.debug("a1: {}".format(a1))
			logger.debug("a2: {}".format(a2))
			logger.debug("expected: {}".format(expected))

			# Report authentication incident
			i = incident("dionaea.modules.python.sip.authentication")
			i.authenticationSuccessful = expected == authLineDict['response']
			i.realm = realm
			i.uri = uri
			i.nonce = authLineDict['nonce']
			i.challengeResponse = authLineDict['response']
			i.expected = expected
			i.report()

			if expected != authLineDict['response']:
				sendUnauthorized(authLineDict['nonce'])
				raise AuthenticationError("Authorization failed")

			logger.info("Authorization succeeded")

class SipServer(connection):
	"""Only UDP connections are supported at the moment"""
	def __init__(self):
		connection.__init__(self, 'udp')
		self._sessions = {}
		self._bindings = {}

	def handle_io_in(self, data):
		sessionkey = (self.local.host, self.local.port, self.remote.host, self.remote.port)
		if sessionkey not in self._sessions:
			self._sessions[sessionkey] = SipSession(self, sessionkey)

		session = self._sessions[sessionkey]
		logger.debug("{}: {}".format(sessionkey, data))
		session.handle_io_in(data)
		return len(data)


class SipSession(connection):
	def __init__(self, server, sessionkey):
		connection.__init__(self, 'udp')
		# we send everything via the servers connection
		self.server = server
		self.sessionkey = sessionkey
		self.remote.host = server.remote.host
		self.remote.port = server.remote.port
		self.local.host = server.local.host
		self.local.port = server.local.port

		# fake a connection entry
		i = incident("dionaea.connection.udp.connect")
		i.con = self
		i.report()

		# Dictionary with SIP sessions (key is Call-ID)
		self._callids = {}

		# Test log entry
		logger.info("SIP Session created")

		# Setup timers
		global g_default_loop

		global _SipSession_sustain_timeout
		self.timers = [
			pyev.Timer(3, 0, g_default_loop, self.__handle_idle_timeout), # idle
			pyev.Timer(_SipSession_sustain_timeout, 0, g_default_loop, self.__handle_sustain_timeout) # sustain
		]

		# start sustain timer
		self.timers[1].start()

		# we have to create a 'special' bistream for this
		# as all sip traffic shares a single connection
		self.bistream = []


	def __handle_idle_timeout(self, watcher, events):
#		logger.warn("self {} SipSession IDLE TIMEOUT watcher".format(self))
		pass

	def __handle_sustain_timeout(self, watcher, events):
		logger.debug("SipSession.__handle_sustain_timeout self {} watcher {}".format(self, watcher))
		self.close()

	def handle_disconnect(self):
		logger.debug("SipSession.handle_disconnect {}".format(self))
		if len(self.bistream) > 0:
			now = datetime.datetime.now()
			dirname = "%04i-%02i-%02i" % (now.year, now.month, now.day)
			dir = os.path.join(g_dionaea.config()['bistreams']['python']['dir'], dirname)
			if not os.path.exists(dir):
				os.makedirs(dir)
			self.fileobj = tempfile.NamedTemporaryFile(delete=False, prefix="Sipsession-" + str(self.local.port) + '-' + self.remote.host + ":" + str(self.remote.port) + "-", dir=dir)
			self.fileobj.write(b"stream = ")
			self.fileobj.write(str(self.bistream).encode())
			self.fileobj.close()
		return False

	def close(self):
		logger.debug("SipSession.close {}".format(self))
		# remove session from server
		if self.sessionkey in self.server._sessions:
			del self.server._sessions[self.sessionkey]

		# close all calls
		for callid in [x for x in self._callids]:
#			logger.debug("closing callid {} call {}".format(callid, self._callids[callid]))
			self._callids[callid].close()
		self._callids = None
		
		# stop timers
		for t in self.timers:
			logger.debug("SipSession timer {} active {} pending {}".format(t,t.active,t.pending))
			if t.active == True or t.pending == True:
#				logger.debug("SipSession Stopping {}".format(t))
				t.stop()

		connection.close(self)

	def send(self, s):
		"""
		The SipSession is not connected, we have to use the origin connection of the server to send.
		"""
		logger.debug('Sending message "{}" to ({}:{})'.format(
			s, self.remote.host, self.remote.port))

		# feed bistream
		self.bistream.append(('out', s))

		# SIP response incident
#		i = incident("dionaea.modules.python.sip.out")
#		i.con = self
#		i.direction = "out"
#		i.msgType = "RESPONSE"
#		i.message = s
#		i.report()
		self.server.send(s, local=(self.local.host,self.local.port),remote=(self.remote.host,self.remoteport))

	def handle_io_in(self, data):

		# feed bistream
		self.bistream.append(('in', data))

		msg = rfc3261.Message(data)

		"""
		# Get byte data and decode to unicode string
		data = data.decode('utf-8')

		# Parse SIP message
		try:
			msgType, firstLine, headers, body = parseSipMessage(data)
		except SipParsingError as e:
			logger.warn("Error while parsing SIP message: {}".format(e))
			return len(data)


		# SIP message incident
#		i = incident("dionaea.modules.python.sip.in")
#		i.con = self
#		i.direction = "in"
#		i.msgType = msgType
#		i.firstLine = firstLine
#		i.sipHeaders = headers
#		i.sipBody = body
#		i.report()

		if msgType == 'INVITE':
			self.sip_INVITE(firstLine, headers, body)
		elif msgType == 'ACK':
			self.sip_ACK(firstLine, headers, body)
		elif msgType == 'OPTIONS':
			self.sip_OPTIONS(firstLine, headers, body)
		elif msgType == 'BYE':
			self.sip_BYE(firstLine, headers, body)
		elif msgType == 'CANCEL':
			self.sip_CANCEL(firstLine, headers, body)
		elif msgType == 'REGISTER':
			self.sip_REGISTER(firstLine, headers, body)
		elif msgType == 'SIP/2.0':
			self.sip_RESPONSE(firstLine, headers, body)
		else:
			logger.warn("Unknown SIP header " + \
				"(supported: INVITE, ACK, OPTIONS, BYE, CANCEL, REGISTER " + \
				"and SIP responses")
		"""
		if msg.method == 'INVITE2':
			self.sip_INVITE(firstLine, headers, body)
		elif msg.method == 'OPTIONS':
			self.handle_OPTIONS(msg)
		else:
			self.handle_unknown(msg)

		"""
		elif msg.method == 'ACK':
			self.sip_ACK(firstLine, headers, body)
		elif msg.method == 'BYE':
			self.sip_BYE(firstLine, headers, body)
		elif msg.method == 'CANCEL':
			self.sip_CANCEL(firstLine, headers, body)
		elif msg.method == 'REGISTER':
			self.sip_REGISTER(firstLine, headers, body)
		elif msg.method == 'SIP/2.0':
			self.sip_RESPONSE(firstLine, headers, body)
		"""
		logger.debug("io_in: returning {}".format(len(data)))
		return len(data)

	def handle_unknown(self, msg):
		res = msg.create_response(501)
		d = res.dumps()
		self.send(res.dumps())

	def sip_INVITE(self, msg):
		global g_sipconfig

		# Print SIP header
		logger.info("Received INVITE")
		for k, v in headers.items():
			logger.debug("SIP header {}: {}".format(k, v))

		if msg.check_headers(["accept", "content-type"], overwrite = True):
			# ToDo: return error
			return

		# Header has to define Content-Type: application/sdp if body contains
		# SDP message. Also, Accept has to be set to sdp so that we can send
		# back a SDP response.
		if msg.headers.get("content-type") != "application/sdp":
			logger.warn("INVITE without SDP message: exit")
			return

		if msg.headers.get("accept") != "application/sdp":
			logger.warn("INVITE without SDP message: exit")
			return

		if msg.sdp == None:
			return

		# Check for SDP body
		if not body:
			logger.warn("INVITE without SDP message: exit")
			return

		# Parse SDP part of session invite
		try:
			sessionDescription, mediaDescriptions = parseSdpMessage(msg._body)
		except SdpParsingError as e:
			logger.warn("Error while parsing SDP message: {}".format(e))
			return

		# Check for all necessary fields
		sdpSessionOwnerParts = sessionDescription['o'].split(' ')
		if len(sdpSessionOwnerParts) < 6:
			logger.warn("SDP session owner field to short: exit")
			return

		logger.debug("Parsed SDP message:")
		for k, v in sessionDescription.items():
			logger.debug("{}: {}".format(k, v))
		for mediaDescription in mediaDescriptions:
			for k, v in mediaDescription.items():
				logger.debug("{}: {}".format(k, v))

		# Get RTP port from SDP media description
		if len(mediaDescriptions) < 1:
			logger.warn("SDP message has to include a media description: exit")
			return
		
		# TODO: look at other mediaDescriptions as well
		mediaDescriptionParts = mediaDescriptions[0]['m'].split(' ')
		if mediaDescriptionParts[0] != 'audio':
			logger.warn("SDP media description has to be of audio type: exit")
			return

		rtpPort = mediaDescriptionParts[1]

		# Read Call-ID field and create new SipCall instance on first INVITE
		# request received (remote host might send more than one because of time
		# outs or because he wants to flood the honeypot)
		logger.debug("Currently active sessions: {}".format(self._callids))
		callId = msg.headers.get("call-id").value
		if callId in self._callids:
			logger.warn("SIP session with Call-ID {} already exists".format(
				callId))
			return

		# Establish a new SIP Call
		newCall = SipCall(self, (self.remote.host, self.remote.port),
			rtpPort, headers)

		# Store session object in sessions dictionary
		self._callids[callId] = newCall

		i = incident("dionaea.connection.link")
		i.parent = self
		i.child = newCall
		i.report()

		try:
			r = newCall.handle_INVITE(headers)
		except AuthenticationError:
			logger.warn("Authentication failed, not creating SIP session")
			newCall.close()
			del newCall

	def sip_ACK(self, requestLine, headers, body):
		logger.info("Received ACK")

		if self.__checkForMissingHeaders(headers):
			return

		# Check if session (identified by Call-ID) exists
		callId = headers['call-id'] 
		if callId not in self._callids:
			logger.warn("Given Call-ID does not belong to any session: exit")
		else:
			try:
				# Handle incoming ACKs depending on current state
				self._callids[callId].handle_ACK(headers, body)
			except AuthenticationError:
				logger.warn("Authentication failed for ACK request")

	def handle_OPTIONS(self, msg):
		logger.info("Received OPTIONS")

		# ToDo: add Contact
		res = msg.create_response(200)
		res.headers.append(rfc3261.Header("INVITE, ACK, CANCEL, OPTIONS, BYE", "Allow"))
		res.headers.append(rfc3261.Header("application/sdp", "Accept"))
		res.headers.append(rfc3261.Header("en", "Accept-Language"))

		self.send(res.dumps())

	def sip_BYE(self, requestLine, headers, body):
		logger.info("Received BYE")

		if self.__checkForMissingHeaders(headers):
			return
		
		# Check if session (identified by Call-ID) exists
		callId = headers['call-id'] 
		if callId not in self._callids:
			logger.warn("Given Call-ID does not belong to any session: exit")
		else:
			try:
				# Handle incoming BYE request depending on current state
				self._callids[callId].handle_BYE(headers, body)
			except AuthenticationError:
				logger.warn("Authentication failed for BYE request")

	def sip_CANCEL(self, requestLine, headers, body):
		logger.info("Received CANCEL")

		# Check mandatory headers
		if self.__checkForMissingHeaders(headers):
			return

		# Get Call-Id and check if there's already a SipSession
		callId = headers['call-id']

		# Get CSeq to find out which request to cancel
		cseqParts = headers['cseq'].split(' ')
		cseqMethod = cseqParts[1]

		if cseqMethod == "INVITE" or cseqMethod == "ACK":
			# Find SipSession and delete it
			if callId not in self._callids:
				logger.warn(
					"CANCEL request does not match any existing SIP session")
				return
			try:
				self._callids[callId].handle_CANCEL(headers)
			except AuthenticationError:
				logger.warn("Authentication failed for CANCEL request")
				return
			else:
				# No RTP connection has been made yet so deleting the session
				# instance is sufficient
				self.__session[callId].close()
		
		# Construct CANCEL response
		global g_sipconfig
		msgLines = []
		msgLines.append("SIP/2.0 " + RESPONSE[OK])
		msgLines.append("Via: SIP/2.0/UDP {}:{}".format(
			g_sipconfig['domain'], g_sipconfig['port']))
		msgLines.append("To: " + headers['from'])
		msgLines.append("From: {0} <sip:{0}@{1}>".format(
			g_sipconfig['user'], g_sipconfig['domain']))
		msgLines.append("Call-ID: " + headers['call-id'])
		msgLines.append("CSeq: " + headers['cseq'])
		msgLines.append("Contact: {0} <sip:{0}@{1}>".format(
			g_sipconfig['user'], self.local.host))

		self.send('\n'.join(msgLines))

	def sip_REGISTER(self, requestLine, headers, body):
		logger.info("Received REGISTER")

	def sip_RESPONSE(self, statusLine, headers, body):
		logger.info("Received a response")
