from functools import reduce
from math import trunc
import sys
import os
import json
import numpy as np
from Libraries.AndroidAPI import AndroidAPI
from Libraries.Files import rmtree, list_files
from Libraries.ApkTool import decompile
from Libraries.Smali import list_smali_files


def extract():
    def process_content(content):
        retval=[]
        list_api=[]
        method=''
        
        for line in content:
            if line.startswith('.method'):
                method=line[:line.find('(')]
                list_api=[]
                continue

            if line.startswith('.end method'):
                retval.append({
                    "method": method,
                    "api": list_api
                })
                method=''
                list_api=[]
                continue

            api=AndroidAPI.parse_android(line)
            if method!='' and api.is_api:
                list_api.append(api.to_dict())

        return retval

    def process_app(source: str):
        try:
            decompile_folder=decompile(source=source, destination='O:\\Riskware')
            smali_files=list_smali_files(decompile_folder)

            contents=list(map(lambda x: open(x).readlines(), smali_files))
            contents=list(map(process_content, contents))
            contents=list(reduce(lambda a, b: np.concatenate((a, b)), contents))
            contents={
                "file_name": os.path.basename(source),
                "type": "riskware",
                "data": contents
            }

            out_file=open('./output/Riskware/{}.json'.format(os.path.basename(source)), 'w')
            json.dump(contents, fp=out_file, indent=4)
            out_file.close()

            rmtree(decompile_folder)
        except:
            pass
        finally:
            os.remove(source)

    list(map(process_app, list_files('O:\\Riskware\\Riskware')))



if __name__ == '__main__':
    if (len(sys.argv) == 1):
        print('missing argument')
        exit(0)
    if sys.argv[1] == 'extract':
        extract()