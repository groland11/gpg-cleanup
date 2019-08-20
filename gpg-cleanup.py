#!/usr/bin/python3
from os.path import expanduser
from pathlib import Path
import sys, re, subprocess, time

HOMEDIR = expanduser("~")
GPGDIR  = HOMEDIR + "/.gnupg"
GPGLOG  = HOMEDIR + "/pubkeys.txt"
GNUPGHOME = ""

fprs = []
delpubkeys = {}

class PubKey:
	def __init__(self, fpr, uid, sig_count, elapsed):
		self.fpr       = fpr
		self.sig_count = sig_count
		self.elapsed   = elapsed
		self.uid       = uid

def check_requirements():
	# Check gpg version

	# Check gpg home directory
	if not Path(GPGDIR).is_dir():
		sys.exit('ERROR: Unable to find GnuPG home directory {}'.format(GPGDIR))

	# Check gpg public key files

check_requirements()

print("Using input file {}".format(GPGLOG))

with open(GPGLOG) as file_log:
	for pubkeys_line in file_log:
		# Search for fingerprint lines
		match = re.search('^fpr:::::::::([A-F0-9]+):', pubkeys_line)
		if match:
			fprs.append(match.group(1))

for fpr in fprs:
	try:
		sig_count = 0
		uid = ""
		start = time.time()
		proc = subprocess.run(["gpg", "--list-sig", fpr], stdout=subprocess.PIPE, check=True, timeout=180, encoding='utf-8')
		elapsed = time.time() - start
		# sig          283B6394008969C8 2019-07-06  [User ID not found]
		for sigs_line in proc.stdout.split('\n'):
			match = re.search('^sig[ \t]+', sigs_line)
			if match:
				sig_count += 1
			match = re.search('^uid[ \t]+(.*)', sigs_line)
			if match:
				uid = match.group(1)

		if sig_count > 200:
			delpubkeys[fpr] = PubKey(fpr, uid, sig_count, elapsed)

	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
		print('ERROR: Unable to list signatures for key {}: {}'.format(fpr, str(e)))
		pass

	print('{} - Number of signatures: {}'.format(fpr, sig_count))

for fpr in delpubkeys:
	ret = raw_input('Do you want to delete public key "{}" ({} signatures in {:.2f} sec)? [y|N] >'.format(fpr, delpubkeys[fpr].sigcount, delpubkeys[fpr].elapsed))
	if ret.lower() == "y":
		try:
			proc = subprocess.run(["gpg", "--delete-keys", fpr], stdout=subprocess.PIPE, check=True, timeout=180, encoding='utf-8')
		except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
			print('ERROR: Unable to delete key {}: {}'.format(fpr, str(e)))
			pass

