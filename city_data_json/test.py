#%%
import json

with open('old_cities.json') as f:
    data = json.load(f)

# state_prev = data[0]["state"]
new_data = {}
for itr in data:
    itr['state'] = itr['state'].lower()
    if itr['state'] in new_data:
        new_data[itr['state']][itr['name'].lower()] = None
    else:
        new_data[itr['state']] = {}
        new_data[itr['state'].lower()][itr['name'].lower()] = None


states = {}
for itr in new_data:
    states[itr.lower()] = None
print(states)

with open('states.json', 'w') as json_file1:
  json.dump(states, json_file1)


with open('result.json', 'w') as json_file2:
  json.dump(new_data, json_file2)


# %%
