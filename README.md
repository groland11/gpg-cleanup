# gpg-cleanup
Cleanup of public keys in your gpg keyring

## Motivation
Recently pgp public keyservers were flooded with **poisoned public keys**. Those keys have been signed by a large number of fake users and therefore contain more signatures than GnuPG can handle. If you try to list those public keys with GnuPG it will take a very long time (maybe 10 minutes, maybe 30 minutes, maybe even days).

gpg-cleanup tries to identify those public keys and help you delete them within a reasonable amount of time. It lets you first create a cache file over night or over the weekend. After you created the cache file, you run gpg-cleanup again to interactively delete all suspicious keys from your public keyring.

Some notable background information links:
- https://lwn.net/Articles/792366/
- https://lwn.net/Articles/792534/

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

1. **Create a cache file** with a list of all your public keys. `gpg --list-keys` might take a long time to finish, so storing the result in a cache file for later use might be a good idea. On my computer with just a handful of public keys, `gpg --list-keys` takes more than 6 minutes.
```
$ gpg-cleanup.py -w ./pubkeys.cache -t 86400
Running gpg ............................................................................................................................................................................................................................................
2019-11-06 08:38:44 INFO     Creating cache file ./pubkeys.cache ...
2019-11-06 08:38:44 INFO     The file ./pubkeys.cache now contains a list of all your public keys (elapsed time: 375.92 sec)
```
Set the timeout to a high value (here: 1 day) so you can let the program run over night or even over the weekend.

2. **List all signatures** of all public keys using the cache file from step 1
```
$ gpg-cleanup.py -r ./pubkeys.cache -t 120
2019-11-06 08:56:50 INFO     Using cache file ./pubkeys.cache ...
2019-11-06 08:56:50 INFO     Processing gpg output ...
2019-11-06 08:56:50 INFO     You have 113 keys in you public keyring.
2019-11-06 08:56:50 INFO     Getting signatures of those public keys ...
2019-11-06 08:56:50 INFO     D305F9A97514CF702C9D247190CA381837AD7647 - Number of signatures: 144
        Marc Deslauriers <marcdeslauriers@videotron.ca>
        Marc Deslauriers <mdeslaur@ubuntu.com>
        Marc Deslauriers <mdeslaur@canonical.com>
        Marc Deslauriers <marc.deslauriers@ubuntu.com>
        Marc Deslauriers <marc.deslauriers@canonical.com>
2019-11-06 08:56:50 INFO     2F1E45C56D00EB019231BFF9215553264598FBA7 - Number of signatures: 1333
        Salvatore Bonaccorso <salvatore.bonaccorso@gmail.com>
        Salvatore Bonaccorso <carnil@cpan.org>
        Salvatore Bonaccorso <carnil@debian.org>
        Salvatore Bonaccorso <bonaccos@ee.ethz.ch>
        Salvatore Bonaccorso <carnil.debian@gmx.net>
        Salvatore Bonaccorso <salvatore.bonaccorso@gmx.net>
        Salvatore Bonaccorso <salvatore.bonaccorso@livenet.ch>
...
2019-11-06 08:56:50 INFO     C5986B4F1257FFA86632CBA746181433FBB75451 - Number of signatures: 102
        Ubuntu CD Image Automatic Signing Key <cdimage@ubuntu.com>
2019-11-06 08:56:50 INFO     843938DF228D22F7B3742BC0D94AA3F0EFE21092 - Number of signatures: 57
        Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>
2019-11-06 09:00:01 INFO     110775B5D101FB36BC6C911BEB774491D9FF06E2 - Number of signatures: 121201
        Tor Browser Developers (signing key) <torbrowser@torproject.org>
2019-11-06 09:00:01 INFO     0B957BB68F870C7F6BACBC4F55B65E5AD6B85D61 - Number of signatures: 52
        Bürger-CERT Newsletter <buerger-cert-newsletter_pgp@newsletter.bund.de>
2019-11-06 09:00:02 INFO     7DE94246A45F8FD06CC82D694BECFA6780121F18 - Number of signatures: 31
        HPI Identity Leak Checker <sec-checker-admin@hpi.de>
2019-11-06 09:00:02 WARNING  Public key with suspicous signatures: 2F1E45C56D00EB019231BFF9215553264598FBA7 (1333 signatures listed in 0.04 sec)
Do you want to delete this key? [y|N] >n
2019-11-06 09:07:14 WARNING  Public key with suspicous signatures: 110775B5D101FB36BC6C911BEB774491D9FF06E2 (121201 signatures listed in 191.39 sec)
Do you want to delete this key? [y|N] >y
```
Set the timeout to a much lower value because you want to interactively delete poisoned keys.

## Troubleshooting

## FAQ
#### Why do you want to delete those keys from your public keyring? The keys themselves are ok, just the signatures are phoney, right?
Yes, the public keys are perfectly fine. But once they are signed by a large number of fake users, they are practically useless. The owner of those public keys could try to delete those signatures and republish his public key, but there is no guarantee that poisoning of his public key won't happen again. The next best thing would be to create a new PGP key and publish it on https://keys.openpgp.org, which does not rely on signatures but rather identifies users by email.

