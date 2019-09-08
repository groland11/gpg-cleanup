import sys, time
from threading import Thread
from keylist import KeyList

class ProgressBar(Thread):
	def __init__(self, statustext):
		Thread.__init__(self)
		self.statustext = statustext

	def run(self):
		#os.popen('tput civis').read()
		print('{} '.format(self.statustext), end='')
		while KeyList.lock1.acquire(blocking=False) == False:
			print('.', end='')
			sys.stdout.flush()
			time.sleep(1)
		print('')
		#os.popen('tput cnorm').read()
