class Plugin(object):
    def __init__(self, row):
        self.id = row[0]
        self.uploaded = row[1]
        self.name = row[2]
        self.path = row[3]
        self.major_version = row[4]
        self.minor_version = row[5]
        self.maintenance_version = row[6]
