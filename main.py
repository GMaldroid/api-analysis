import sys
import os
import json
import numpy as np
import pandas as pd
import polars as pl
from functools import reduce
from Libraries.AndroidAPI import AndroidAPI
from Libraries.Files import rmtree, list_files
from Libraries.ApkTool import decompile
from Libraries.Smali import list_smali_files
from Libraries.Csv import save_int_csv, save_float_csv, load_int_csv
from Libraries.Pkl import save_pkl, load_pkl
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import RFE
from sklearn.decomposition import PCA
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, f1_score, recall_score, precision_score
from multiprocess.pool import Pool
from matplotlib import pyplot as plt
from numba import jit, cuda

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
    ranking = json.load(open("./output/ranking/ranking.json", "r"))["data"]
    for i in range(100, len(ranking), 100):
        top_api = ranking[:i]
        result = []
        for element in top_api:
            result.append(element["api"])
        
        result = {
            "description": f"Top {i} api was ranked by sklearn RFE",
            "count": len(result),
            "data": result
        }

        open(f"output/ranking/top-api/ranking{i}.json", "w").write(json.dumps(result, indent=4))
    


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
    
    return result

    pd.DataFrame(result, columns=["Label"]).to_csv("./output/label.csv")
    pass

def ranking():
    data = pd.read_csv("./output/app_api.csv", index_col=0, header=0).to_numpy()
    label = pd.read_csv("./output/label.csv", index_col=0, header=0).to_numpy()
    x_train, x_test, y_train, y_test = train_test_split(data, label, test_size=0.3, random_state=42)
    
    model = SVC(kernel="linear")
    selector = RFE(estimator=model, n_features_to_select=1, step=1, verbose=1)
    print("fit")
    selector.fit(x_train, y_train.ravel())
    save_pkl("./output/ranking1800.pkl", selector)

def ranking_pca():
    data_frame = pd.read_csv("./output/app_api_label.csv", index_col=0, header=0)
    training_header = list(data_frame.columns)
    training_header.remove("Label")

    train_data = data_frame[training_header]    
    pca = PCA()
    pca.fit(train_data)

    save_float_csv("./output/full.csv", pca.components_)

    pass

def attach_ranking():
    result = []
    api_dataset = json.load(open("output/number-of-call-for-app/top_api.json", "r"))["data"]
    ranking = load_pkl("output/ranking/ranking.pkl").ranking_

    for i in range(len(api_dataset)):
        ele = dict()
        ele["api"] = api_dataset[i]
        ele["rank"] = int(ranking[i])
        result.append(ele)
    
    result.sort(key=lambda x: x["rank"], reverse=False)

    result = {
        "description": "API Dataset ranking with sklearn RFE",
        "count": len(result),
        "data": result
    }

    
    open("./output/ranking/ranking.json", "w").write(json.dumps(result, indent=4))

def create_app_api(api_dataset_path: str, save_path: str):
    api_dataset = json.load(open(api_dataset_path, "r"))["data"]

    def create_row(file: str, label: str):
        print(file)
        content = json.load(open(file, "r"))["data"]
        result = np.zeros((len(api_dataset)), dtype=int)

        for method in content:
            for api_call in method["api"]:
                if api_call["full_api_call"] in api_dataset:
                    result[api_dataset.index(api_call["full_api_call"])] = 1
        result = result.tolist()
        result.append(label)
        return result
    
    result = []
    pool = Pool(10)
    result.append(list(pool.map(lambda x: create_row(x, "Adware"), list_files("./output/extracted-data/Adware")[:20])))
    result.append(list(pool.map(lambda x: create_row(x, "Banking"), list_files("./output/extracted-data/Banking")[:20])))
    result.append(list(pool.map(lambda x: create_row(x, "Bening"), list_files("./output/extracted-data/Benign")[:20])))
    result.append(list(pool.map(lambda x: create_row(x, "Riskware"), list_files("./output/extracted-data/Riskware")[:20])))
    result.append(list(pool.map(lambda x: create_row(x, "Smsmalware"), list_files("./output/extracted-data/SMS")[:20])))
    matrix = list(reduce(lambda x, y: np.concatenate((x, y)), result))

    api_dataset.append("Label")

    pd.DataFrame(matrix, columns=api_dataset).to_csv(save_path)
    return matrix

def create_invoke():
    api_dataset = json.load(open("output\\ranking\\top-api\\ranking400.json", "r"))["data"]
    invoke_matrix = np.zeros((len(api_dataset), len(api_dataset)), dtype=np.int32)

    def process(app):
        print(app)
        invoke_static = set()
        invoke_virtual = set()
        invoke_direct = set()
        invoke_super = set()
        invoke_interface = set()
        data = json.load(open(app, "r"))["data"]
        for method in data:
            apis = method["api"]
            for api in apis:
                if api["full_api_call"] in api_dataset:
                    invoke = api["invoke"]
                    if invoke == 'invoke-static':
                        invoke_static.add(api_dataset.index(api["full_api_call"]))
                    elif invoke == 'invoke-virtual':
                        invoke_virtual.add(api_dataset.index(api["full_api_call"]))
                    elif invoke == 'invoke-direct':
                        invoke_direct.add(api_dataset.index(api["full_api_call"]))
                    elif invoke == 'invoke-super':
                        invoke_super.add(api_dataset.index(api["full_api_call"]))
                    elif invoke == 'invoke-interface':
                        invoke_interface.add(api_dataset.index(api["full_api_call"]))
        all_type = []
        all_type.append(invoke_static)
        all_type.append(invoke_virtual)
        all_type.append(invoke_direct)
        all_type.append(invoke_super)
        all_type.append(invoke_interface)

        return all_type

    result = []
    result = np.concatenate((result, list_files("./output/extracted-data/Adware")))
    result = np.concatenate((result, list_files("./output/extracted-data/Banking")))
    result = np.concatenate((result, list_files("./output/extracted-data/Benign")))
    result = np.concatenate((result, list_files("./output/extracted-data/Riskware")))
    result = np.concatenate((result, list_files("./output/extracted-data/SMS")))
    apps = list(map(process, result))
    for i, app in enumerate(apps):
        print(f'process {i}')
        for type in app:
            type = list(type)
            for i in range(len(type)):
                for j in range(i, len(type)):
                    invoke_matrix[type[i]][type[j]] = 1
    
    pd.DataFrame(invoke_matrix, index=api_dataset, columns=api_dataset).to_csv('./output/invoke.csv')



def create_method():
    api_dataset = json.load(open("output\\ranking\\top-api\\ranking400.json", "r"))["data"]
    method_matrix = np.zeros((len(api_dataset), len(api_dataset)), dtype=np.int32)

    def process(app: str):
        print(app)

        in_app = []
        data = json.load(open(app, "r"))["data"]
        for method in data:
            buffer = []
            apis = method["api"]
            for api in apis:
                if api["full_api_call"] in api_dataset:
                    buffer.append(api_dataset.index(api["full_api_call"]))
            in_app.append(buffer)
        return in_app

    result = []
    result = np.concatenate((result, list_files("./output/extracted-data/Adware")))
    result = np.concatenate((result, list_files("./output/extracted-data/Banking")))
    result = np.concatenate((result, list_files("./output/extracted-data/Benign")))
    result = np.concatenate((result, list_files("./output/extracted-data/Riskware")))
    result = np.concatenate((result, list_files("./output/extracted-data/SMS")))
    pool = Pool(5)
    apps = list(pool.map(process, result))
    for i, app in enumerate(apps):
        print(f"process app {i}")
        for buffer in app:
            for i in range(len(buffer)):
                for j in range(i, len(buffer)):
                    method_matrix[buffer[i]][buffer[j]] = 1


    save_int_csv("./output/method.csv", method_matrix)
    pass
def create_package():
    api_dataset = json.load(open("output\\ranking\\top-api\\ranking400.json", "r"))["data"]
    api_dataset.sort()
    print(api_dataset)
    

def analysis_api():
    def analysis(training_data_path: str, index):
        print(training_data_path)

        data_frame = pd.read_csv(training_data_path, index_col=0, header=0)
        training_header = list(data_frame.columns)
        training_header.remove("Label")

        train_data = data_frame[training_header]
        train_label = data_frame["Label"]

        x_train, x_test, y_train, y_test = train_test_split(train_data, train_label, test_size=0.3, random_state=50)

        model = KNeighborsClassifier(n_neighbors=5)
        model.fit(x_train, y_train)
        predict = model.predict(x_test)

        return {
            "index": index,
            "accuracy": accuracy_score(y_test, predict),
            "f1": f1_score(y_test, predict, average='weighted'),
            "recall": recall_score(y_test, predict, average='weighted'),
            "precision": precision_score(y_test, predict, average='weighted')
        }

    result = []
    for i in range(100, 2701, 100):
        result.append(analysis(f"output\\analysis\\training_data\\training_data_{i}_api.csv", i))

    result = {
        "description": "Training result",
        "data": result
    }

    open("output\\analysis\\k_neighbor_5.json", "w").write(json.dumps(result, indent=4))

def draw():
    training_data = json.load(open("output\\analysis\\decision-tree-default.json", "r"))["data"]
    x = []
    accuracy = []
    recall = []
    f1 = []
    precision = []
    for ele in training_data:
        x.append(ele["index"])
        accuracy.append(ele["accuracy"] * 100)
        recall.append(ele["recall"] * 100)
        f1.append(ele["f1"] * 100)
        precision.append(ele["precision"] * 100)
    
    plt.plot(x, accuracy)
    plt.xlabel("number of api")
    plt.ylabel("percent")
    plt.suptitle("decision tree accuracy")
    plt.savefig("output/analysis/images/decision_tree-accuracy.png")
    plt.show()
    pass

def for_quan():
    
    pass

def app_api_split():
    app_api_dp = pd.read_csv("output\\app_api_label_400.csv", index_col=0, header=0)
    app_api = app_api_dp.to_numpy()

    result = app_api[0:1000]

    for i, app in enumerate(app_api):
        if app[400] == 'Banking':
            result = np.concatenate((result, app_api[i:i+1000]))
            break

    for i, app in enumerate(app_api):
        if app[400] == 'Bening':
            result = np.concatenate((result, app_api[i:i+1000]))
            break
    
    for i, app in enumerate(app_api):
        if app[400] == 'Riskware':
            result = np.concatenate((result, app_api[i:i+1000]))
            break

    for i, app in enumerate(app_api):
        if app[400] == 'Smsmalware':
            result = np.concatenate((result, app_api[i:i+1000]))
            break
    
    print(result.shape)
    pd.DataFrame(result, columns=app_api_dp.columns).to_csv("output\\5000app\\app_api_label_5000_app.csv")
    pass

def app_api_split_test():
    app_api_dp = pd.read_csv("output\\app_api_label_400.csv", index_col=0, header=0)
    adware = app_api_dp[app_api_dp["Label"] == "Adware"]
    banking = app_api_dp[app_api_dp["Label"] == "Banking"]
    benign = app_api_dp[app_api_dp["Label"] == "Bening"]
    riskware = app_api_dp[app_api_dp["Label"] == "Riskware"]
    smsmalware = app_api_dp[app_api_dp["Label"] == "Smsmalware"]

    adware = adware.iloc[1000:,:]
    banking = banking.iloc[1000:,:]
    benign = benign.iloc[1000:,:]
    riskware = riskware.iloc[1000:,:]
    smsmalware = smsmalware.iloc[1000:,:]

    result = pd.concat([adware, banking, benign, riskware, smsmalware])
    pd.DataFrame(result.to_numpy(), columns=app_api_dp.columns).to_csv("output\\5000app\\app_api_label_test_for_5000_app_training.csv")
    
if __name__ == '__main__':
    if (len(sys.argv) > 1):
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
        if sys.argv[1] == 'ranking':
            ranking()
        if sys.argv[1] == 'ranking_pca':
            ranking_pca()
        if sys.argv[1] == 'attach_ranking':
            attach_ranking()
        if sys.argv[1] == 'analysis':
            analysis_api()
        if sys.argv[1] == 'create-method':
            create_method()
        if sys.argv[1] == 'create-invoke':
            create_invoke()
        if sys.argv[1] == 'create-package':
            create_package()
        if sys.argv[1] == "draw":
            draw()
        if sys.argv[1] == 'for-quan':
            for_quan()
        if sys.argv[1] == 'app-api-split':
            app_api_split()
        if sys.argv[1] == 'app-api-split-test':
            app_api_split_test()
        exit(0)
    df = pl.read_csv("output\\app_api_label_400.csv")
    print(df.select([pl.col("Label").sort()]))
