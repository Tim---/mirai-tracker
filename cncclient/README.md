This is a client for the MIRAI Command and Control (C&C) servers.
It can be used to analyze the attack commands sent by the C&C servers.

## Installation
```sh
pip3 install -r requirements.txt
```

## Running
```sh
python3 cncclient.py
```
## Example output
```
# www.mufoscam.org:23 connected
# fuck1.bagthebook.com:23 connected
# our.bklan.ru:23 connected
# sdrfafasyy.top:23 connected
2016-10-31 18:16:39 www.mufoscam.org:23: {'options': {}, 'targets': ['41.57.81.0/24'], 'duration': 120, 'attack_type': 'GREETH'}
2016-10-31 18:20:29 www.mufoscam.org:23: {'options': {}, 'targets': ['41.57.81.0/24'], 'duration': 600, 'attack_type': 'GREIP'}
```