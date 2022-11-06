import sys
import os
import json
import numpy as np
from functools import reduce
from Libraries.AndroidAPI import AndroidAPI
from Libraries.Files import rmtree, list_files
from Libraries.ApkTool import decompile
from Libraries.Smali import list_smali_files


def extract():
    def process_content(content: list[str]):
        retval = []
        list_api = []
        method = ''
        
        for line in content:
            if line.startswith('.method'):
                method = line[:line.find('(')]
                list_api = []
                continue

            if line.startswith('.end method'):
                retval.append({
                    "method": method,
                    "api": list_api
                })
                method = ''
                list_api = []
                continue

            api = AndroidAPI.parse_android(line)
            if method != '' and api.is_api:
                list_api.append(api.to_dict())

        return retval

    def process_app(source: str, type: str, destination: str, output: str):
        try:
            decompile_folder = decompile(source=source, destination=destination)
            smali_files = list_smali_files(decompile_folder)

            contents = list(map(lambda x: open(x).readlines(), smali_files))
            contents = list(map(process_content, contents))
            contents = list(reduce(lambda a, b: np.concatenate((a, b)), contents))
            contents = {
                "file_name": os.path.basename(source),
                "type": type,
                "data": contents
            }

            out_file = open('{}/{}.json'.format(output, os.path.basename(source)), 'w')
            json.dump(contents, fp=out_file, indent=4)
            out_file.close()

            rmtree(decompile_folder)
        except:
            pass
        finally:
            os.remove(source)

    list(map(lambda x: process_app(source=x, 
                                   type='benign', 
                                   destination='D:\\Benign', 
                                   output='./output/Benign'), list_files('D:\\Benign\\Benign')))


def total():
    def process_content(result, file):
        content = json.load(open(file))
        data = content["data"]

        for method in data:
            for api in method["api"]:
                if api["full_api_call"] in result:
                    result[api["full_api_call"]] += 1
                else:
                    result[api["full_api_call"]] = 1

        return result

    contents = dict(reduce(process_content, list_files("./output/Benign"), dict()))
    open("./output/total-call/Benign.json", "w").write(json.dumps(contents, indent=4))

def transform():
    data = json.load(open("./output/total-call/SMS.json", "r"))
    result = list()
    for key in data.keys():
        result.append({
            "name": key,
            "count": data[key]
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    result = {
        "type": "SMS",
        "data": result
    }
    open("./output/SMS.json", "w").write(json.dumps(result, indent=4))
    pass

if __name__ == '__main__':
    if (len(sys.argv) == 1):
        print('missing argument')
        exit(0)
    if sys.argv[1] == 'extract':
        extract()
    if sys.argv[1] == 'total':
        total()
    if sys.argv[1] == 'transform':
        transform()