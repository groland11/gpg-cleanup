# gpg-cleanup
Cleanup of public keys in your gpg keyring

## Motivation
Recently pgp public keyservers were flooded with **poisoned public keys**. Those keys have been signed by a large number of fake users and therefore contain more signatures than GnuPG can handle. If you try to list those pubic keys with GnuPG it will take a very long time (maybe 10 minutes, maybe 30 minutes, maybe even longer). gpg-cleanup tries to identify those public keys and help you delete them.

Some notable background links:
https://lwn.net/Articles/792366/
https://lwn.net/Articles/792534/

### How do I know if my GnuPG public keyring contains those poisoned public keys?
- Listing all of your public keys takes a very long time. It seems as if the gpg command hangs.
- When "gpg --list-keys" finally finishes, there are public keys in the result list with a very large number of signatures (maybe a couple of hundreds, maybe even thousands).
- Your public keyring has a much larger disk size than usual (maybe several MB for just a handful of public keys, maybe even larger).

Check the size of your public keyring:

`ls -hl ~/.gnupg/pubring.*`

List all signatures of all keys in your public keyring and save them to a file for later investigation. This may take a long time.

`gpg --list-sigs | tee -a sigs.list`

## Requirements
- Python 3.6 or higher
- GnuPG 2.1 or higher

Note that starting from GnuPG 2.1, public keys may be stored in one of two files:
- ~/.gnupg/pubring.gpg
- ~/.gnupg/pubring.kbx

Either one of those two files may be used by GnuPG and may be very large.

## Command line options
```
gpg-cleanup.py [-h] [-v] [-w [WRITECACHE] | -r [READCACHE]]
                      [-t TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Show program's version and exit.
  -w [WRITECACHE], --writecache [WRITECACHE]
                        Create cache file (default: '~/pubkeys.cache') and exit.
  -r [READCACHE], --readcache [READCACHE]
                        Read from cache file (default: '~/pubkeys.cache').
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds for gpg (default: 120).
```

## Example usage
Here is an example how you might use this tool:

1. **Create a cache** file with a list of all your public keys. `gpg --list-keys` might take a long time to finish, so storing the result in a cache file for later use might be a good idea. On my computer with just a handful of public keys, `gpg --list-keys` takes more than 6 minutes.
```
$ gpg-cleanup.py -c ./pubkeys.cache
Creating cache file ./pubkeys.cache ...
OK: The file ./pubkeys.cache now contains a list of all your public keys (elapsed time: 375.92 sec)
```
2. **List all signatures** of all public keys using the cache file
```
$ gpg-cleanup.py -r ./pubkeys.cache
```

## Troubleshooting

## FAQ
#### Why do you want to delete those keys from your public keyring? The keys themselves are ok, just the signatures are phoney, right?
Yes, the public keys are perfectly fine. But once they are signed by a large number of fake users, they are practically useless. The owner of those public keys could try to delete those signatures and republish his public key, but there is no guarantee that poisoning of his public key won't happen again. The next best thing would be to create a new PGP key and publish it on https://keys.openpgp.org, which does not rely on signatures but rather identifies users by email.

