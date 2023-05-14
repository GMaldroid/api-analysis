import os
import stat

def list_files(path: str):
    return [path + "/" + f for f in os.listdir(path)]

def rmtree(path: str):
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            filename = os.path.join(root, name)
            os.chmod(filename, stat.S_IWUSR)
            os.remove(filename)
        for name in dirs:
            os.rmdir(os.path.join(root, name))
    os.rmdir(path)