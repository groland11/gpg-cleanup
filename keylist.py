import time, sys, subprocess, threading, re
from threading import Thread
from pubkey import Pubkey

class KeyList(Thread):
	lock1 = threading.Lock()

	def __init__(self, timeout):
		Thread.__init__(self)
		self.lines = []
		self.timeout = timeout
		self.exc = None

	# Run gpg in thread to get public key list
	def run(self):
		self.lock1.acquire(blocking=False)
		try:
			proc = subprocess.run(['gpg', '--with-colons', '--list-keys'], stdout=subprocess.PIPE, check=True, timeout=self.timeout, encoding='utf-8')
		except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
			self.exc = e
			sys.exit('ERROR: Unable to list public keys (process error, timeout): {}'.format(str(e)))
		else:
			for pubkey_line in proc.stdout.split('\n'):
				self.lines.append(pubkey_line)
			#time.sleep(5)
		finally:
			self.lock1.release()

	# Write keylist to file
	def serialize(self, file_write):
		try:
			with open(file_write, 'w') as file_cache:
				for pubkey_line in self.lines:
					file_cache.write(pubkey_line + '\n')
		except IOError as e:
			sys.exit('ERROR: Unable to write cache file {}: {}'.format(file_write, str(e)))
	
	# Read keylist from file into instance variable 'lines'
	# Returns list of Pubkey objects
	def deserialize(self, file_read=None):
		pubkeys_return = []
	
		if file_read:
			try:
				with open(file_read, 'r') as file_cache:
					self.lines = file_cache.readlines()
			except IOError as e:
				sys.exit('ERROR: Unable to read cache file {}: {}'.format(file_read, str(e)))
		
		if self.lines:
			fpr = ''
			uids = []
			for pubkey_line in self.lines:
				match = re.search('^pub:', pubkey_line)
				if match:
					if fpr != '':
						pubkeys_return.append(Pubkey(fpr, uids))
					fpr = ''
					uids = []
					continue
				match = re.search('^fpr:::::::::([A-F0-9]+):', pubkey_line)
				if match:
					fpr = match.group(1)
					continue
				match = re.search('^uid:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:([^:]*):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:', pubkey_line)
				if match:
					uids.append(match.group(1))
					continue
	
			if fpr != '':
				pubkeys_return.append(Pubkey(fpr, uids))
	
		return pubkeys_return

