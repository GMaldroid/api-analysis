import re

class AndroidAPI:
    def __init__(self, is_api: bool, invoke = "", package = "", method_name = "") -> None:
        self.is_api = is_api
        self.invoke = invoke
        self.package = package 
        self.method_name = method_name
        self.full_api_call = package + ";->" + method_name

    def to_dict(self):
        return {
            "invoke": self.invoke,
            "package": self.package,
            "method_name": self.method_name,
            "full_api_call": self.full_api_call
        }
    
    # ============== static =====================
    def parse(string_api: str):
        string_api = string_api.strip()
        if AndroidAPI.__is_api(string_api) == False:
            return AndroidAPI(is_api=False)

        head = 0
        tail = string_api.find(" ")
        if head != -1 and tail != -1:
            invoke = string_api[head:tail]
        else:
            invoke = ""

        head = string_api.find('}, ')
        tail = string_api.find(';')
        if head != -1 and tail != -1:
            package = string_api[head+3 : tail]
        else:
            package = ""

        method_name = ""
        if string_api.find(";->") != -1:
            for i in range(string_api.find(';->') + 3, len(string_api)):
                if not (string_api[i].isalpha() or string_api[i] == '<' or string_api[i] == '>'):
                    break
                method_name = method_name + string_api[i]
        return AndroidAPI(True, invoke, package, method_name)
    
    def parse_android(string_api: str):
        api = AndroidAPI.parse(string_api=string_api)
        if api.package.startswith("Landroid") or api.package.startswith("Ljava"):
            return api
        else:
            return AndroidAPI(is_api=False)


    #================ private =====================
    def __is_api(string_api: str):
        if re.search(r'^invoke', string_api):
            return True
        else:
            return False