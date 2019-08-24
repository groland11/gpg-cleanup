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

import sys, re, subprocess, time
import argparse

from os import access, W_OK
from os.path import expanduser
from pathlib import Path

HOMEDIR = expanduser("~")
GPGDIR  = HOMEDIR + "/.gnupg"
GPGLOG  = HOMEDIR + "/pubkeys.cache"
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
	# Check home directory
	if not Path(HOMEDIR).is_dir(): 
		sys.exit('ERROR: Invalid home directory "{}"'.format(HOMEDIR))

	# Check gpg version
	try:
		output = subprocess.check_output("gpg --version | egrep -i -o \"[0-9.]+\" | head -1", shell=True, universal_newlines=True, timeout=10)
		ver = output.strip()
		if ver < "2.1":
			sys.exit('ERROR: gpg version must be at least 2.1 (your version: {})'.format(ver))
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
		sys.exit('ERROR: Unable to retrieve gpg version: {}'.format(str(e)))

	# Check gpg home directory
	if not Path(GPGDIR).is_dir() or not access(GPGDIR, W_OK):
		sys.exit('ERROR: Unable to access GnuPG home directory "{}"'.format(GPGDIR))

	# Check gpg public key files

def add_fingerprint(line):
	match = re.search('^fpr:::::::::([A-F0-9]+):', line)
	if match:
		fprs.append(match.group(1))

# Check requirements, command line
check_requirements()

ap = argparse.ArgumentParser()
group = ap.add_mutually_exclusive_group()
ap.add_argument('-v', '--version', action='version', version='%(prog)s 0.1a', help="Show program's version and exit.")
group.add_argument("-w", "--writecache", required=False, nargs='?', const=GPGLOG, help="Create cache file (default: '~/pubkeys.cache') and exit.")
group.add_argument("-r", "--readcache", required=False, nargs='?', const=GPGLOG, help="Read from cache file (default: '~/pubkeys.cache').")
ap.add_argument("-t", "--timeout", required=False, default=120, type=int, help="Timeout in seconds for gpg (default: 120).")
args = ap.parse_args()

# Write public keys to cache file and exit
if args.writecache:
	print("Creating cache file {} ...".format(args.writecache))
	start_time = time.time()
	try:
		proc = subprocess.run(["gpg", "--with-colons", "--list-keys"], stdout=subprocess.PIPE, check=True, timeout=args.timeout, encoding='utf-8')
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
		sys.exit('ERROR: Unable to list public keys: {}'.format(str(e)))

	try:
		with open(args.writecache, 'w') as file_cache:
			for pubkey_line in proc.stdout.split('\n'):
				file_cache.write(pubkey_line + '\n')
	except IOError as e:
		sys.exit('ERROR: Unable to write cache file {}: {}'.format(args.writecache, str(e)))
	else:
		elapsed_time = time.time() - start_time
		print("OK: The file {} now contains a list of all your pubic keys (elapsed time: {:.2f} sec)".format(args.writecache, elapsed_time))
	sys.exit()

# Retrieve public keys fingerprints from cache file
if args.readcache:
	if Path(args.readcache).is_file():
		print("Using cache file {} ...".format(args.readcache))
	
		with open(args.readcache) as file_cache:
			for pubkey_line in file_cache:
				add_fingerprint(pubkey_line)
# Retrieve public keys fingerprints from gpg
else:
	try:
		proc = subprocess.run(["gpg", "--with-colons", "--list-keys"], stdout=subprocess.PIPE, check=True, timeout=args.timeout, encoding='utf-8')
	except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
		sys.exit('ERROR: Unable to list public keys: {}'.format(str(e)))
	else:
		for pubkey_line in proc.stdout.split('\n'):
			add_fingerprint(pubkey_line)

# List signatures for each public key to find out if key is ok
for fpr in fprs:
	sig_count = 0
	uid = ""
	elapsed = 0.0
	try:
		start = time.time()
		proc = subprocess.run(["gpg", "--list-sig", fpr], stdout=subprocess.PIPE, check=True, timeout=20, encoding='utf-8')
		elapsed = time.time() - start
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
		if elapsed == 0.0:
			elapsed = time.time() - start
		print('ERROR: Unable to list signatures for key {}: {}'.format(fpr, str(e)))
		delpubkeys[fpr] = PubKey(fpr, uid, sig_count, elapsed)
		pass

	print('{} - Number of signatures: {}'.format(fpr, sig_count))

# Delete suspicious public keys from keyring
for fpr in delpubkeys:
	ret = input('Do you want to delete public key "{}" ({} signatures listed in {:.2f} sec)? [y|N] >'.format(fpr, delpubkeys[fpr].sig_count, delpubkeys[fpr].elapsed))
	if ret.lower() == "y":
		try:
			proc = subprocess.run(["gpg", "--delete-keys", fpr], stdout=subprocess.PIPE, check=True, timeout=180, encoding='utf-8')
		except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
			print('ERROR: Unable to delete key {}: {}'.format(fpr, str(e)))
			pass
		else:
			print('OK: Successfully deleted public key {}'.format(fpr))

