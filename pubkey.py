class Pubkey:
    def __init__(self, fpr, uids, sigcount=0, elapsed=0.0):
        self.fpr = fpr
        self.uids = uids
        self.sigcount = sigcount
        self.elapsed = elapsed
