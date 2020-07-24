import hashlib
class File_Hash:
    def Discover_Hash(self, filepath):
        hash = hashlib.md5()
        with open(filepath,"rb") as f:
            read_until = 0
            while read_until != b'':
                read_until = f.read(1024)
                hash.update(read_until)
        return hash.hexdigest()
