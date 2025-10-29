import json, os
fname = "db/passwords_maine.json"
print("Exists:", os.path.exists(fname))
if os.path.exists(fname):
    with open(fname, "r") as f:
        print(json.dumps(json.load(f), indent=4))
