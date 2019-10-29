class Pubkey:
    '''Structure holding information about a public key

    Attributes
    ----------
    fpr : string
        Fingerprint of public key

    uids : list
        List of user ids associated with public key

    sigcount : int
        Number of signatures for that public key

    elapsed : float
        Time in seconds it took to retrieve public key
    '''

    def __init__(self, fpr, uids, sigcount=0, elapsed=0.0):
        '''
        Parameters
        ----------
        fpr : string
            Fingerprint of public key

        uids : list
            List of user ids associated with public key

        sigcount : int, optional
            Number of signatures (default: 0)

        elapsed : float, optional
            Number of seconds it took to retrieve public key
            (default: 0.0)
        '''

        self.fpr = fpr
        self.uids = uids
        self.sigcount = sigcount
        self.elapsed = elapsed
