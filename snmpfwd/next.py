class Numbers:
    current = 0
    def getId(self):
        self.current += 1
        if self.current > 65535:
            self.current = 0
        return self.current

numbers = Numbers()

getId = numbers.getId
