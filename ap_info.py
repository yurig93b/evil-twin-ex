import typing
from dataclasses import dataclass
from typing import Union
import copy

@dataclass
class AccessPointInfo:
    ssid: str
    bssid: str
    channel: int
    crypto: typing.Set
    raw_stats: dict

    def to_dict(self):
        d = copy.deepcopy(self.__dict__)
        d['crypto'] = list[d['crypto']]
        return d