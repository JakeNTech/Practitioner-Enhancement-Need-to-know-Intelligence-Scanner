# Description: Collect key registry keys/values from the identified files into a single table.
# Author: @JakeNTech
# Dependencies: Registry
# Version: 1
# Date: 20/01/2023

import json
from Registry import Registry

## https://github.com/williballenthin/python-registry
def rec(key, depth=0):
    print("\t" * depth + key.path())

    for subkey in key.subkeys():
        rec(subkey, depth + 1)

def main(reg_file_path,reg_type):
    # Decided which keys to extract
    with open("./scripts/plugins/registry_keys.json") as f:
        reg_keys_json = json.load(f)

    if reg_type == "SOFTWARE":
        reg_keys_json = reg_keys_json["SOFTWARE"]
    elif reg_type == "SYSTEM":
        reg_keys_json = reg_keys_json["SYSTEM"]
    elif reg_type == "NTUSER":
        reg_keys_json = reg_keys_json["NTUSER"]

    # Extract keys and place into 2D array
    try:
        reg = Registry.Registry(reg_file_path)
        values = []
        for reg_key in reg_keys_json.keys():
            sub_value = reg_keys_json[reg_key]
            try:
                key = reg.open(reg_key)
                for value in [v for v in key.values() if v.value_type() == Registry.RegSZ or v.value_type() == Registry.RegExpandSZ]:
                    if len(sub_value) == 0:
                        values.append([reg_type,reg_key, value.name(), value.value()])
                    else:
                        for i in range(0,len(sub_value)):
                            if value.name() == sub_value[i]:
                                values.append([reg_type,reg_key+"\\"+sub_value[i], value.name(), value.value()])

            except Registry.RegistryKeyNotFoundException:
                pass
    except:
        values = []

    return values

__artifacts__ = {
    "Registry File Parsing": (
        "File Parsing",
        "hive,key,value_name,value_value",
        main),
}

# if __name__ == "__main__":
    # main("./","SOFTWARE")
    # print(main("../../test_files/f06.reg","SOFTWARE"))
    # reg = Registry.Registry("../../test_files/f07.reg")
    # rec(reg.root())