import sys
import os
import json
import numpy as np
import pandas as pd
from functools import reduce
from Libraries.AndroidAPI import AndroidAPI
from Libraries.Files import rmtree, list_files
from Libraries.ApkTool import decompile
from Libraries.Smali import list_smali_files
from Libraries.Csv import save_int_csv


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
        list_api_call = []

        for method in data:
            for api_object in method["api"]:
                if api_object["full_api_call"] not in list_api_call:
                    list_api_call.append(api_object["full_api_call"])
        
        for api in list_api_call:
            if api in result:
                result[api] += 1
            else:
                result[api] = 1

        return result

    contents = dict(reduce(process_content, list_files("./output/extract-data/SMS"), dict()))
    open("./output/total-call/SMS.json", "w").write(json.dumps(contents, indent=4))

def transform():
    data = json.load(open("output/total-call/SMS.json", "r"))
    result = list()
    for key in data.keys():
        result.append({
            "name": key,
            "count": data[key]
        })
    result.sort(key=lambda x: x["count"], reverse=True)
    result = {
        "type": "smsmalware",
        "data": result
    }
    open("./output/number-of-call-for-app/smsmalware.json", "w").write(json.dumps(result, indent=4))
    pass

def filter():
    adware = json.load(open("./output/number-of-call/Adware.json", "r"))
    banking = json.load(open("./output/number-of-call/Banking.json", "r"))
    benign = json.load(open("./output/number-of-call/Benign.json", "r"))
    riskware = json.load(open("./output/number-of-call/Riskware.json", "r"))
    sms = json.load(open("./output/number-of-call/SMS.json", "r"))

    adware_name = [f["name"] for f in adware["data"]]
    banking_name = [f["name"] for f in banking["data"]]
    benign_name = [f["name"] for f in benign["data"]]
    riskware_name = [f["name"] for f in riskware["data"]]
    sms_name = [f["name"] for f in sms["data"]]
    
    adware_result = []
    banking_result = []
    bening_result = []
    riskware_result = []
    sms_result = []

    print("riskware")
    sms_nm = []
    for api in sms_name:
        if (api not in adware_name) and (api not in banking_name) and (api not in benign_name) and (api not in riskware_name):
            sms_nm.append(api)
    print(f"size of sms not match {len(sms_nm)}")
    for api in sms["data"]:
        if api["name"] in sms_nm:
            sms_result.append(api)
    open("./output/api-not-match/SMS.json", "w").write(
        json.dumps(
            {
                "description": "Top API call only on smsmalware",
                "type": "smsmalware", 
                "data": sms_result
            }
            , indent=4
        )
    )

def topapi():
    adware = json.load(open("output\\number-of-call-for-app\\Adware.json", "r"))["data"]
    banking = json.load(open("output\\number-of-call-for-app\\Banking.json", "r"))["data"]
    bening = json.load(open("output\\number-of-call-for-app\\Bening.json", "r"))["data"]
    riskware = json.load(open("output\\number-of-call-for-app\\riskware.json", "r"))["data"]
    smsmalware = json.load(open("output\\number-of-call-for-app\\smsmalware.json", "r"))["data"]

    top_api = []

    for i in range(1000):
        if adware[i]["name"] not in top_api:
            top_api.append(adware[i]["name"])
        if banking[i]["name"] not in top_api:
            top_api.append(adware[i]["name"])
        if bening[i]["name"] not in top_api:
            top_api.append(bening[i]["name"])
        if riskware[i]["name"] not in top_api:
            top_api.append(bening[i]["name"])
        if smsmalware[i]["name"] not in top_api:
            top_api.append(smsmalware[i]["name"])

    top_api.sort()

    top_api = {
        "description": "Top API in list adware, banking, bening, riskware and smsmalware",
        "count": len(top_api),
        "data": top_api
    }
    open("./output/number-of-call-for-app/top_api.json", "w").write(json.dumps(top_api, indent=4))

def create_app_api():
    api_dataset = json.load(open("output\\number-of-call-for-app\\top_api.json", "r"))["data"]

    def create_row(file: str, label: str):
        print(file)
        content = json.load(open(file, "r"))["data"]
        result = np.zeros((len(api_dataset)), dtype=int)

        for method in content:
            for api_call in method["api"]:
                if api_call["full_api_call"] in api_dataset:
                    result[api_dataset.index(api_call["full_api_call"])] = 1
        return result

    result = []
    result.append(list(map(lambda x: create_row(x, "Adware"), list_files("./output/extract-data/Adware"))))
    result.append(list(map(lambda x: create_row(x, "Banking"), list_files("./output/extract-data/Banking"))))
    result.append(list(map(lambda x: create_row(x, "Bening"), list_files("./output/extract-data/Benign"))))
    result.append(list(map(lambda x: create_row(x, "Riskware"), list_files("./output/extract-data/Riskware"))))
    result.append(list(map(lambda x: create_row(x, "Smsmalware"), list_files("./output/extract-data/SMS"))))


    matrix = list(reduce(lambda x, y: np.concatenate((x, y)), result))


    matrix = pd.DataFrame(matrix, columns=api_dataset)
    matrix.to_csv(path_or_buf="./output/app_api.csv")
    pass

def create_label():
    result = []
    for _ in list_files("./output/extract-data/Adware"):
        result.append("Adware")
    for _ in list_files("./output/extract-data/Banking"):
        result.append("Banking")
    for _ in list_files("./output/extract-data/Benign"):
        result.append("Bening")
    for _ in list_files("./output/extract-data/Riskware"):
        result.append("Riskware")
    for _ in list_files("./output/extract-data/SMS"):
        result.append("Smsmalware")

    pd.DataFrame(result, columns=["Label"]).to_csv("./output/label.csv")
    pass

def selection():
    data = pd.read_csv("./output/app_api.csv", index_col=0, header=0).to_numpy()
    label = pd.read_csv("./ouput/label.csv", index_col=0, header=0).to_numpy()
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
    if sys.argv[1] == 'filter':
        filter()
    if sys.argv[1] == 'topapi':
        topapi()
    if sys.argv[1] == 'create':
        create_app_api()
    if sys.argv[1] == 'selection':
        selection()
    if sys.argv[1] == 'label':
        create_label()