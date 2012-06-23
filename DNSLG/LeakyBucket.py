default_bucket_size = 20

import time

class LeakyBucket():

    def __init__(self, size=default_bucket_size):
        self.size = size
        self.content = 0
        self.last_check = time.time()
        
    def update(self):
        duration = time.time() - self.last_check
        offset = duration 
        if self.content > offset:
            self.content -= offset
        elif self.content == 0:
            pass
        else:
            self.content = 0
        self.last_check = time.time()

    def add(self, amount=1):
        if not self.full():
            self.content += amount

    def full(self):
        self.update()
        return self.content >= self.size
