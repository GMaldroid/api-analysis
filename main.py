from Libraries.AndroidAPI import AndroidAPI


api = AndroidAPI.parse("invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;")
print(api.invoke)
print(api.package)
print(api.method_name)
print(api.full_api_call)