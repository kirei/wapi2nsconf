import dataclasses
import json
from typing import Any


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        return super().default(o)


def function_to_json(data: Any, sort_keys: bool = True, indent: int = 4) -> str:
    return json.dumps(data, sort_keys=sort_keys, indent=indent, cls=EnhancedJSONEncoder)
