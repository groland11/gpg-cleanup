# gpg-cleanup
Cleanup of public keys in your gpg keyring

## Motivation
Recently pgp public keyservers were flooded with **poisoned public keys**. Those keys have been signed by a large number of fake users and therefore contain more signatures than GnuPG can handle. If you try to list those pubic keys with GnuPG it will take a very long time (maybe 10 minutes, maybe 30 minutes, maybe even longer). gpg-cleanup tries to identify those public keys and help you delete them.

### How do I know if my GnuPG public keyring contains those poisoned public keys?
- Listing all your public keys takes a very long time. It seems as if the gpg command hangs.
- When "gpg --list-keys" finally finishes, there are public keys in the result list with a very large number of signatures (maybe a couple of hundreds, maybe even thousands).
- Your public keyring has a large disk size (maybe 20 MB, maybe even larger).

Check the size of your public keyring:

$ ls -hl ~/.gnupg/pubring.*

## Requirements
- Python 3.6 or higher
- GnuPG 2.1 or higher

## Command line options

## Example usage

## Troubleshooting

## FAQ
### Why do you want to delete those keys from your public keyring? The keys themselves are ok, just the signatures are phoney, right?
Yes, the public keys are perfectly fine. But once they are signed by a large number of fake users, they are practically useless. The owner of those public keys could try to delete those signatures and republish his public key, but there is no guarantee that poisoning this public key won't happen again. The next best thing would be to create a new PGP key and publish it on https://keys.openpgp.org, which does not rely on signatures but rather identifies users by email.
