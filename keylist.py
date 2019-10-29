import re
import subprocess
import sys
import threading
import time  # noqa: F401

from pubkey import Pubkey
from threading import Thread


class KeyList(Thread):
    '''List of all gpg public keys

    This class basically serves as a cache for gpg public keys.
    Persistence is achieved by writing and reading to a text file.

    Attributes
    ----------
    exc : Exception
        Current error state of object

    lines : list
        List of gpg public keys as strings, unformatted from gpg output

    timeout : int
        Timeout in seconds for all external operations

    Methods
    -------
    __init__(timeout)
        Initialize class. Set timeout for all external operations.

    run()
        Retrieve public keys from gpg in separate thread.

    serialize(file_write)
        Write public keys to cache file.

    deserialize(file_read)
        Read and return public keys from cache file.
    '''

    # Lock is needed to synchronize with other threads
    # (e.g. class ProgressBar)
    lock1 = threading.Lock()

    def __init__(self, timeout):
        '''
        Parameters
        ----------
        timeout : int
            Timeout in seconds for all external operations
        '''

        Thread.__init__(self)
        self.lines = []
        self.timeout = timeout
        self.exc = None

    def run(self):
        '''Run gpg in thread to get public key list.

        Method is inherited from parent class Thread.
        To synchronize with other running threads, lock has to be
        aquired at start (non-blocking) and released at exit of method
        in all cases.

        sys.exit() does not end application, just current thread.
        '''

        self.lock1.acquire(blocking=False)
        try:
            proc = subprocess.run(
                                  ['gpg', '--with-colons', '--list-keys'],
                                  stdout=subprocess.PIPE, check=True,
                                  timeout=self.timeout, encoding='utf-8')
        except(
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired) as e:
            self.exc = e
            sys.exit('ERROR: Unable to list public keys '
                     '(process error, timeout): {}'.format(str(e)))
        else:
            for pubkey_line in proc.stdout.split('\n'):
                self.lines.append(pubkey_line)
            time.sleep(5)
        finally:
            self.lock1.release()

    def serialize(self, file_write):
        '''Write keylist to file.

        Parameters
        ----------
        file_write : string
            Full path of cache file to write to
        '''

        try:
            with open(file_write, 'w') as file_cache:
                for pubkey_line in self.lines:
                    file_cache.write(pubkey_line + '\n')
        except IOError as e:
            sys.exit('ERROR: Unable to write cache file {}: '
                     '{}'.format(file_write, str(e)))

    def deserialize(self, file_read=None):
        '''Read keylist from file or internal list.

        Parameters
        ----------
        file_read : string, optional
            Full path of cache file to read from

        Returns
        -------
        List of Pubkey objects
        '''

        pubkeys_return = []

        if file_read:
            try:
                with open(file_read, 'r') as file_cache:
                    self.lines = file_cache.readlines()
            except IOError as e:
                sys.exit('ERROR: Unable to read cache file {}: '
                         '{}'.format(file_read, str(e)))

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
                match = re.search('^uid:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:'
                                  '[^:]*:[^:]*:([^:]*):[^:]*:[^:]*:[^:]*:[^:]*'
                                  ':[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:',
                                  pubkey_line)
                if match:
                    uids.append(match.group(1))
                    continue

            if fpr != '':
                pubkeys_return.append(Pubkey(fpr, uids))

        return pubkeys_return
