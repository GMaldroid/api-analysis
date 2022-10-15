import os

def decompile(source: str, destination: str):
    if not os.path.exists(destination):
        return
    filename = os.path.basename(source).replace('.apk', '')
    decompile_folder = os.path.join(destination, "extract-" + filename)
    os.system("apktool d -f -r -o {} {}".format(decompile_folder, source))
    return decompile_folder