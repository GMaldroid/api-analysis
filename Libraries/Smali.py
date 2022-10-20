import os


def list_smali_files(path: str):
    smalis = []
    for root, _, filenames in os.walk(path):
        for filename in filenames:
            if filename.endswith('.smali'):
                smalis.append(os.path.join(root, filename))
    return smalis

