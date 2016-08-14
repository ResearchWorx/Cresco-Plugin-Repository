class Admin(object):
    def __init__(self, row):
        self.id = row[0]
        self.username = row[1]
        self.email = row[3]
        self.first_name = row[4]
        self.last_name = row[5]