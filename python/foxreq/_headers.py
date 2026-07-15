"""Immutable ordered response headers with duplicate preservation."""


class Headers:
    __slots__ = ("_items",)

    def __init__(self, items=()):
        normalized = []
        for item in items:
            if isinstance(item, (str, bytes, bytearray, memoryview)):
                raise TypeError("header items must be name/value pairs")
            try:
                name, value = item
            except (TypeError, ValueError) as exc:
                raise TypeError("header items must be name/value pairs") from exc
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("response header names and values must be strings")
            if not name or any(character in name for character in "\r\n\0"):
                raise ValueError("invalid response header name")
            if any(character in value for character in "\r\n\0"):
                raise ValueError("invalid response header value")
            normalized.append((name, value))
        self._items = tuple(normalized)

    def __len__(self):
        return len(self._items)

    def __iter__(self):
        return iter(self._items)

    def __getitem__(self, name):
        if not isinstance(name, str):
            raise TypeError("header lookup name must be a string")
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __repr__(self):
        return "Headers({!r})".format(self._items)

    def items(self):
        return self._items

    def get(self, name, default=None):
        if not isinstance(name, str):
            raise TypeError("header lookup name must be a string")
        folded = name.lower()
        for current_name, value in self._items:
            if current_name.lower() == folded:
                return value
        return default

    def get_all(self, name):
        if not isinstance(name, str):
            raise TypeError("header lookup name must be a string")
        folded = name.lower()
        return tuple(
            value
            for current_name, value in self._items
            if current_name.lower() == folded
        )
