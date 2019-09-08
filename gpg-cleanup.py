#!/usr/bin/env python3
# coding: UTF-8
#
# Copyright (c) 2019
#
# Permission is hereby granted, free of charge, to any person 
# obtaining a copy of this software and associated documentation 
# files (the "Software"), to deal in the Software without 
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or 
# sell copies of the Software, and to permit persons to whom 
# the Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall 
# be included in all copies or substantial portions of the 
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# ToDo:
# - Print expiration date
# - Print user ids in delete dialog
# - Parameter for max. number of signatures

import sys, os, re, subprocess, time, threading
import argparse

from os import access, W_OK
from os.path import expanduser
from pathlib import Path
from pubkey import Pubkey
from progressbar import ProgressBar
from keylist import KeyList

HOMEDIR = expanduser('~')
GPGDIR  = HOMEDIR + '/.gnupg'
GPGLOG  = HOMEDIR + '/pubkeys.cache'
GNUPGHOME = ''

pubkeys = []
delpubkeys = {}

def check_requirements():
	# Check home directory
	if not Path(HOMEDIR).is_dir(): 
		sys.exit('ERROR: Invalid home directory "{}"'.format(HOMEDIR))

	# Check gpg version
	try:
		output = subprocess.check_output('gpg --version | egrep -i -o "[0-9.]+" | head -1', shell=True, universal_newlines=True, timeout=10)
		ver = output.strip()
		if ver < '2.1':
			sys.exit('ERROR: gpg version must be at least 2.1 (your version: {})'.format(ver))
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
		sys.exit('ERROR: Unable to retrieve gpg version: {}'.format(str(e)))

	# Check gpg home directory
	if not Path(GPGDIR).is_dir() or not access(GPGDIR, W_OK):
		sys.exit('ERROR: Unable to access GnuPG home directory "{}"'.format(GPGDIR))

	# Check gpg public key files

# Check requirements, command line, initialize threading
check_requirements()

ap = argparse.ArgumentParser()
group = ap.add_mutually_exclusive_group()
ap.add_argument('-v', '--version', action='version', version='%(prog)s 0.1a', help='Show program\'s version and exit.')
group.add_argument('-w', '--writecache', required=False, nargs='?', const=GPGLOG, help='Create cache file (default: \'~/pubkeys.cache\') and exit.')
group.add_argument('-r', '--readcache', required=False, nargs='?', const=GPGLOG, help='Read from cache file (default: \'~/pubkeys.cache\').')
ap.add_argument('-t', '--timeout', required=False, default=120, type=int, help='Timeout in seconds for gpg (default: 120).')
args = ap.parse_args()


# Transfer public keys from cache file into object array and continue
if args.readcache:
	if Path(args.readcache).is_file():
		print('Using cache file {} ...'.format(args.readcache))
		keylist = KeyList(args.timeout)
		pubkeys = keylist.deserialize(file_read=args.readcache)
	else:
		sys.exit('ERROR: Unable to read cache file "{}"'.format(args.readcache))

# Retrieve public keys directly from gpg
else:
	# Initialize threading to access gpg
	start_time = time.time()

	keylist = KeyList(args.timeout)
	progressbar = ProgressBar('Running gpg')

	keylist.start()
	progressbar.start()

	keylist.join()
	progressbar.join()

	if keylist.exc:
		sys.exit('ERROR: Unable to retrieve public keys: {}'.format(keylist.exc))

	# Write public keys to cache file and exit
	if args.writecache:

		print('Creating cache file {} ...'.format(args.writecache))
		keylist.serialize(args.writecache)
		elapsed_time = time.time() - start_time

		print('OK: The file {} now contains a list of all your public keys (elapsed time: {:.2f} sec)'.format(args.writecache, elapsed_time))
		sys.exit()

	# Deserialize public keys into object array and continue
	else:
		print('Processing gpg output ...')
		pubkeys = keylist.deserialize()
		elapsed_time = time.time() - start_time

# Give some statistics
print('You have {} keys in you public keyring.'.format(len(pubkeys)))
print('Getting signatures of those public keys ...')

# List signatures for each public key to find out if key is suspicious
for pubkey in pubkeys:
	sig_count = 0
	uid = ''
	elapsed = 0.0

	try:
		start = time.time()
		proc = subprocess.run(['gpg', '--list-sig', pubkey.fpr], stdout=subprocess.PIPE, check=True, timeout=args.timeout, encoding='utf-8')
		elapsed = time.time() - start
		for sigs_line in proc.stdout.split('\n'):
			match = re.search('^sig[ \t]+', sigs_line)
			if match:
				sig_count += 1
			match = re.search('^uid[ \t]+(.*)', sigs_line)
			if match:
				uid = match.group(1)

		if sig_count > 200:
			delpubkeys[pubkey.fpr] = Pubkey(pubkey.fpr, pubkey.uids, sig_count, elapsed)

	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
		if elapsed == 0.0:
			elapsed = time.time() - start
		print('ERROR: Unable to list signatures for key {}: {}'.format(pubkey.fpr, str(e)))
		delpubkeys[pubkey.fpr] = Pubkey(pubkey.fpr, pubkey.uids, sig_count, elapsed)
		pass

	print('{} - Number of signatures: {}'.format(pubkey.fpr, sig_count))
	for uid in pubkey.uids:
		print('\t{}'.format(uid))

# Delete suspicious public keys from keyring
if len(delpubkeys) == 0:
	print('OK: No suspicious signatures found in your public keyring')
else:
	for fpr in delpubkeys:
		print('Public key with suspicous signatures: {} ({} signatures listed in {:.2f} sec)'.format(fpr, delpubkeys[fpr].sigcount, delpubkeys[fpr].elapsed))
		ret = input('Do you want to delete this key? [y|N] >')
		if ret.lower() == 'y':
			try:
				proc = subprocess.run(['gpg', '--delete-keys', fpr], stdout=subprocess.PIPE, check=True, timeout=180, encoding='utf-8')
			except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
				print('ERROR: Unable to delete key {}: {}'.format(fpr, str(e)))
				pass
			else:
				print('OK: Successfully deleted public key {}'.format(fpr))

