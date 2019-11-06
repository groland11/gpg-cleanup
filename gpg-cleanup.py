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
#
# TODO: Next features
# - Print expiration date
# - Print user ids in delete dialog
# - Parameter for max. number of signatures

import argparse
import logging
from os import access, W_OK
from os.path import expanduser
from pathlib import Path
import re
import subprocess
import sys
import time

from keylist import KeyList
from progressbar import ProgressBar
from pubkey import Pubkey

HOMEDIR = expanduser('~')
GPGDIR = HOMEDIR + '/.gnupg'
GPGLOG = HOMEDIR + '/pubkeys.cache'
GNUPGHOME = ''

pubkeys = []
delpubkeys = {}


def check_requirements():
    '''Check all requirements necessary to run the program.

    If requirements are not met, program will be terminated
    immediately with a short error message.

    Parameters
    ----------
    '''

    # Check home directory
    if not Path(HOMEDIR).is_dir():
        sys.exit('ERROR: Invalid home directory "{}"'.format(HOMEDIR))

    # Check gpg version
    try:
        output = subprocess.check_output(
            'gpg --version | egrep -i -o "[0-9.]+" | head -1',
            shell=True, universal_newlines=True, timeout=10)
        ver = output.strip()
        if ver < '2.1':
            sys.exit(
                'ERROR: gpg version must be at least 2.1 '
                '(your version: {})'.format(ver))
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        sys.exit('ERROR: Unable to retrieve gpg version: {}'.format(str(e)))

    # Check gpg home directory
    if not Path(GPGDIR).is_dir() or not access(GPGDIR, W_OK):
        sys.exit(
            'ERROR: Unable to access GnuPG home directory "{}"'.format(GPGDIR))

    # TODO: Check gpg public key files


def main():
    # Check requirements, command line, initialize logging
    check_requirements()

    ap = argparse.ArgumentParser()
    group = ap.add_mutually_exclusive_group()
    ap.add_argument(
        '-v', '--version', action='version', version='%(prog)s 0.1a',
        help='Show program\'s version and exit.')
    group.add_argument(
        '-w', '--writecache', required=False, nargs='?', const=GPGLOG,
        help='Create cache file (default: \'~/pubkeys.cache\') and exit.')
    group.add_argument(
        '-r', '--readcache', required=False, nargs='?', const=GPGLOG,
        help='Read from cache file (default: \'~/pubkeys.cache\').')
    ap.add_argument(
        '-t', '--timeout', required=False, default=120, type=int,
        help='Timeout in seconds for gpg (default: 120).')
    args = ap.parse_args()

    logformat = "%(asctime)s %(levelname)-8s %(message)s"
    logging.basicConfig(format=logformat, level=logging.INFO, datefmt="%Y-%m-%d %H:%M:%S")

    # Decide if we have to read public gpg keys from cache file or
    # read them on the fly from gpg
    if args.readcache:
        # Transfer public keys from cache file into object list and continue
        if Path(args.readcache).is_file():
            logging.info('Using cache file %s ...', args.readcache)
            keylist = KeyList(args.timeout)
            pubkeys = keylist.deserialize(file_read=args.readcache)
        else:
            sys.exit(
                'ERROR: Unable to read cache file '
                '"{}"'.format(args.readcache))
    else:
        # Retrieve public keys directly from gpg
        # Initialize threading to access gpg
        start_time = time.time()

        keylist = KeyList(args.timeout)
        progressbar = ProgressBar('Running gpg')

        keylist.start()
        progressbar.start()

        keylist.join()
        progressbar.join()

    if keylist.exc:
        msg = 'ERROR: Unable to retrieve public keys'
        hint = ''
        if type(keylist.exc) is subprocess.TimeoutExpired:
            hint = 'Use -t command line option to extend timeout'
        sys.exit('{}: {}\n{}'.format(msg, keylist.exc, hint))

    # Write public keys to cache file and exit
    if args.writecache:
        logging.info('Creating cache file %s ...', args.writecache)
        keylist.serialize(args.writecache)
        elapsed_time = time.time() - start_time

        logging.info(
            'The file %s now contains a list of all your public keys '
            '(elapsed time: '
            '%.2f sec)', args.writecache, elapsed_time)
        sys.exit()

    # Deserialize public keys into object list and continue
    else:
        logging.info('Processing gpg output ...')
        pubkeys = keylist.deserialize()
        elapsed_time = time.time() - start_time

    # All public gpg keys should be stored in object list by now
    # Give some statistics
    logging.info('You have %d keys in you public keyring.', len(pubkeys))
    logging.info('Getting signatures of those public keys ...')

    # List signatures for each public key to find out if key is suspicious
    for pubkey in pubkeys:
        sig_count = 0
        uid = ''
        elapsed = 0.0

        try:
            start = time.time()
            proc = subprocess.run(
                ['gpg', '--list-sig', pubkey.fpr],
                stdout=subprocess.PIPE,
                check=True,
                timeout=args.timeout,
                encoding='utf-8'
                )
            elapsed = time.time() - start
            for sigs_line in proc.stdout.split('\n'):
                match = re.search('^sig[ \t]+', sigs_line)
                if match:
                    sig_count += 1
                match = re.search('^uid[ \t]+(.*)', sigs_line)
                if match:
                    uid = match.group(1)

            if sig_count > 200:
                delpubkeys[pubkey.fpr] = Pubkey(
                                                pubkey.fpr, pubkey.uids,
                                                sig_count, float(elapsed))

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            # Something went wrong while trying to retrieve public key
            # signatures
            if elapsed == 0.0:
                elapsed = time.time() - start
            logging.info('Unable to list signatures for key '
                  '%s: %s', pubkey.fpr, str(e))
            delpubkeys[pubkey.fpr] = Pubkey(
                                            pubkey.fpr, pubkey.uids,
                                            sig_count, float(elapsed))
            pass

        logging.info('%s - Number of signatures: %d', pubkey.fpr, sig_count)
        for uid in pubkey.uids:
            print('\t{}'.format(uid))

    # Public keys with suspicious signatures should be stored
    # in object list right now
    if len(delpubkeys) == 0:
        logging.info('No suspicious signatures found in your public keyring')
    else:
        # Let the user decide which public keys to delete from keyring
        for fpr in delpubkeys:
            logging.warning(
                'Public key with suspicous signatures: %s '
                '(%s signatures listed in '
                '%s sec)', fpr,
                             delpubkeys[fpr].sigcount,
                             delpubkeys[fpr].elapsed)
            ret = input('Do you want to delete this key? [y|N] >')
            if ret.lower() == 'y':
                try:
                    proc = subprocess.run(
                        ['gpg', '--delete-keys', fpr],
                        stdout=subprocess.PIPE,
                        check=True,
                        timeout=180,
                        encoding='utf-8')
                except(
                        subprocess.CalledProcessError,
                        subprocess.TimeoutExpired) as e:
                    logging.error(
                        'Unable to delete key %s: '
                        '%s', fpr, str(e))
                    pass
                else:
                    logging.info('Successfully deleted public key %s', fpr)


if __name__ == '__main__':
    main()
