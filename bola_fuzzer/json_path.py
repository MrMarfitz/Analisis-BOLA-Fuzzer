from typing import Any


def extract_json_path(data: Any, path: str) -> Any:
    """Small JSON path reader for simple paths like $.token, $.data[0].id, or $[0].id."""
    if not path.startswith("$"):
        raise ValueError(f"JSON path must start with '$': {path}")

    current = data
    cursor = 1
    while cursor < len(path):
        char = path[cursor]
        if char == ".":
            cursor += 1
            start = cursor
            while cursor < len(path) and path[cursor] not in ".[":
                cursor += 1
            key = path[start:cursor]
            if not isinstance(current, dict) or key not in current:
                raise KeyError(f"Key '{key}' not found while reading {path}")
            current = current[key]
        elif char == "[":
            end = path.index("]", cursor)
            index_text = path[cursor + 1 : end]
            if not index_text.isdigit():
                raise ValueError(f"Only numeric list indexes are supported: {path}")
            index = int(index_text)
            if not isinstance(current, list) or index >= len(current):
                raise IndexError(f"Index {index} not found while reading {path}")
            current = current[index]
            cursor = end + 1
        else:
            raise ValueError(f"Unsupported JSON path token '{char}' in {path}")
    return current
