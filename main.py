import sys
import os
import json
import numpy as np
import pandas as pd
from collections import Counter
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
        print(file)
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

    contents = dict(reduce(process_content, list_files("D:/NCKH-2022/repo/Train_1500/input/SMS_300"), dict()))
    open("./output/do-an/total-call/format1/SMS_300.json", "w").write(json.dumps(contents, indent=4))

def transform():
    data = json.load(open("output/do-an/total-call/format1/SMS.json", "r"))
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
    open("./output/do-an/total-call/format2/SMS.json", "w").write(json.dumps(result, indent=4))
    pass

def group():
    adware = json.load(open("output/do-an/total-call/format2/Adware.json", "r"))
    banking = json.load(open("output/do-an/total-call/format2/Banking.json", "r"))
    benign = json.load(open("output/do-an/total-call/format2/Bening.json", "r"))
    riskware = json.load(open("output/do-an/total-call/format2/Riskware.json", "r"))
    sms = json.load(open("output/do-an/total-call/format2/SMS.json", "r"))

    for top in range(10, 310, 10):
        result = set()

        for api in adware["data"][:top]:
            result.add(api["name"])
        for api in banking["data"][:top]:
            result.add(api["name"])
        for api in benign["data"][:top]:
            result.add(api["name"])
        for api in riskware["data"][:top]:
            result.add(api["name"])
        for api in sms["data"][:top]:
            result.add(api["name"])
        
        result = {
            "description": f"set of top {top} api from adware, banking, benign, riskware, sms",
            "count": len(result),
            "data": list(result)
        }
        
        open(f"./output/do-an/top-api/top-{top}.json", "w").write(json.dumps(result, indent=4))

def filter():
    adware = json.load(open("output/statistical-api-call/Adware.json", "r"))
    banking = json.load(open("./output/statistical-api-call/Banking.json", "r"))
    benign = json.load(open("./output/statistical-api-call/Benign.json", "r"))
    riskware = json.load(open("./output/statistical-api-call/riskware.json", "r"))
    sms = json.load(open("./output/statistical-api-call/smsmalware.json", "r"))

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

def create_app_api():
    for top in range(10, 310, 10):
        api_dataset_path = f"output/do-an/top-api/top-{top}.json"
        save_path = f"output/do-an/matrix/{top}/app-api.csv"

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
        result.append(list(pool.map(lambda x: create_row(x, "Adware"), list_files("D:/NCKH-2022/repo/Train_1500/input/Adware_300"))))
        result.append(list(pool.map(lambda x: create_row(x, "Banking"), list_files("D:/NCKH-2022/repo/Train_1500/input/Banking_300"))))
        result.append(list(pool.map(lambda x: create_row(x, "Bening"), list_files("D:/NCKH-2022/repo/Train_1500/input/Benign_300"))))
        result.append(list(pool.map(lambda x: create_row(x, "Riskware"), list_files("D:/NCKH-2022/repo/Train_1500/input/Riskware_300"))))
        result.append(list(pool.map(lambda x: create_row(x, "Smsmalware"), list_files("D:/NCKH-2022/repo/Train_1500/input/SMS_300"))))
        matrix = list(reduce(lambda x, y: np.concatenate((x, y)), result))

        api_dataset.append("Label")

        pd.DataFrame(matrix, columns=api_dataset).to_csv(save_path)

def create_invoke():
    api_dataset = json.load(open("output/do-an/top-api/top-200.json", "r"))["data"]
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
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Adware_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Banking_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Benign_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Riskware_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/SMS_300")))
    pool = Pool(10)
    apps = list(pool.map(process, result))
    for i, app in enumerate(apps):
        print(f'process {i}')
        for type in app:
            type = list(type)
            for i in range(len(type)):
                for j in range(i, len(type)):
                    invoke_matrix[type[i]][type[j]] = 1
    
    pd.DataFrame(invoke_matrix, index=api_dataset, columns=api_dataset).to_csv('output/do-an/matrix/200/invoke.csv')



def create_method():
    api_dataset = json.load(open("output/do-an/top-api/top-200.json", "r"))["data"]
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
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Adware_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Banking_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Benign_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/Riskware_300")))
    result = np.concatenate((result, list_files("D:/NCKH-2022/repo/Train_1500/input/SMS_300")))
    pool = Pool(10)
    apps = list(pool.map(process, result))
    for i, app in enumerate(apps):
        print(f"process app {i}")
        for buffer in app:
            for i in range(len(buffer)):
                for j in range(i, len(buffer)):
                    method_matrix[buffer[i]][buffer[j]] = 1


    pd.DataFrame(method_matrix, index=api_dataset, columns=api_dataset).to_csv('output/do-an/matrix/200/method.csv')

def create_package():
    api_dataset = json.load(open("output/do-an/top-api/top-200.json", "r"))["data"]
    package_matrix = np.zeros((len(api_dataset), len(api_dataset)), dtype=np.int32)
    for api_i in range(len(api_dataset)):
        package_matrix[api_i][api_i] = 1
        for api_j in range(api_i + 1, len(api_dataset)):
            if api_dataset[api_i][:api_dataset[api_i].index(';->')] == api_dataset[api_j][
                                                                        :api_dataset[api_j].index(';->')]:
                package_matrix[api_i][api_j] = 1
                package_matrix[api_j][api_i] = 1
    pd.DataFrame(package_matrix, index=api_dataset, columns=api_dataset).to_csv("output/do-an/matrix/200/package.csv")

    

def analysis_api():
    def analysis(training_data_path: str, index):
        print(training_data_path)

        data_frame = pd.read_csv(training_data_path, index_col=0, header=0)
        training_header = list(data_frame.columns)
        training_header.remove("Label")

        train_data = data_frame[training_header]
        train_label = data_frame["Label"]

        x_train, x_test, y_train, y_test = train_test_split(train_data, train_label, test_size=0.3, random_state=50)

        model = SVC(kernel="sigmoid")
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
    for i in range(10, 310, 10):
        result.append(analysis(f"output/do-an/matrix/{i}/app-api.csv", i))

    result = {
        "description": "Training result",
        "data": result
    }

    open("output/do-an/analysis/svc-sigmoid.json", "w").write(json.dumps(result, indent=4))

def agv():
    tree = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]
    knb = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]
    liner = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]
    poly = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]
    rbf = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]
    sigmoid = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]

    result = []
    for i in  range(30):
        acc = (tree[i]["accuracy"] + knb[i]["accuracy"] + liner[i]["accuracy"] + poly[i]["accuracy"] + rbf[i]["accuracy"] + sigmoid[i]["accuracy"]) / 5
        f1 = (tree[i]["f1"] + knb[i]["f1"] + liner[i]["f1"] + poly[i]["f1"] + rbf[i]["f1"] + sigmoid[i]["f1"]) / 5
        recall = (tree[i]["recall"] + knb[i]["recall"] + liner[i]["recall"] + poly[i]["recall"] + rbf[i]["recall"] + sigmoid[i]["recall"]) / 5
        precision = (tree[i]["precision"] + knb[i]["precision"] + liner[i]["precision"] + poly[i]["precision"] + rbf[i]["precision"] + sigmoid[i]["precision"]) / 5

        result.append({
            "index": tree[i]["index"],
            "accuracy": acc,
            "f1": f1,
            "recall": recall,
            "precision": precision
        })
    
    result = {
        "description": "avg calc",
        "data": result
    }

    open("output/do-an/analysis/avg.json", "w").write(json.dumps(result, indent=4))

def draw():
    training_data = json.load(open("output/do-an/analysis/svc-sigmoid.json", "r"))["data"]
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
    
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2)
    ax1.plot(x, accuracy)
    ax1.set_title("accuracy")
    ax1.set_xlabel("apis")
    ax1.set_ylabel("percent")

    ax2.plot(x, recall)
    ax2.set_title("recall")
    ax2.set_xlabel("apis")
    ax2.set_ylabel("percent")

    ax3.plot(x, f1)
    ax3.set_title("f1")
    ax3.set_xlabel("apis")
    ax3.set_ylabel("percent")

    ax4.plot(x, precision)
    ax4.set_title("precision")
    ax4.set_xlabel("apis")
    ax4.set_ylabel("percent")

    plt.suptitle("svc sigmoid")
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

    adware = adware.iloc[600:,:]
    banking = banking.iloc[600:,:]
    benign = benign.iloc[600:,:]
    riskware = riskware.iloc[600:,:]
    smsmalware = smsmalware.iloc[600:,:]

    result = pd.concat([adware, banking, benign, riskware, smsmalware])
    pd.DataFrame(result.to_numpy(), columns=app_api_dp.columns).to_csv("output\\3000app\\test.csv")
    
if __name__ == '__main__':
    if (len(sys.argv) > 1):
        if sys.argv[1] == 'extract':
            extract()
        if sys.argv[1] == 'total':
            total()
        if sys.argv[1] == 'transform':
            transform()
        if sys.argv[1] == 'group':
            group()
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
        if sys.argv[1] == 'agv':
            agv()
        if sys.argv[1] == 'analysis':
            analysis_api()
        if sys.argv[1] == 'create-app-api':
            create_app_api()
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
    
    datas = json.load(open(r"output\analysis\svc-rbf.json", "r"))["data"]
    for data in datas:
        index = data["index"]
        acc = round(data["accuracy"], 4)
        f1 = round(data["f1"], 4)
        recall = round(data["recall"], 4)
        precision = round(data["precision"], 4)
        print(f"{index} {acc} {f1} {recall} {precision}")

