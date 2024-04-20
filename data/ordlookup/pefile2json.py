#!/usr/bin/env python3
import yaml
from pefile import ordlookup
#from PE import ordlookup

for dll, ord_names in ordlookup.ords.items():
    if isinstance(list(ord_names.keys())[0], bytes):
        ord_names = {k: v.decode("utf-8") for k, v in ord_names.items()}
    
    yaml_data = yaml.dump(ord_names, allow_unicode=True, default_flow_style=False)

    if isinstance(dll, bytes):
        dll = dll.decode("utf-8")
    file_name = dll + ".yml"
    with open(file_name, 'w', encoding='utf-8') as yaml_file:
        yaml_file.write(yaml_data)

