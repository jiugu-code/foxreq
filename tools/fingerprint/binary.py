"""Small bounded reader for network-byte-order protocol structures."""

from typing import Union

from .errors import ParseError


BytesLike = Union[bytes, bytearray, memoryview]


class Reader:
    """Read a byte slice without permitting silent truncation or overrun."""

    def __init__(
        self,
        data: BytesLike,
        base_offset: int = 0,
        path: str = "input",
    ) -> None:
        self._data = memoryview(data)
        self._cursor = 0
        self._base_offset = base_offset
        self.path = path

    @property
    def remaining(self) -> int:
        return len(self._data) - self._cursor

    @property
    def offset(self) -> int:
        return self._base_offset + self._cursor

    def take(self, size: int) -> bytes:
        if size < 0:
            raise ParseError("negative size", self.offset, self.path)
        if size > self.remaining:
            raise ParseError("truncated input", self.offset, self.path)

        start = self._cursor
        self._cursor += size
        return bytes(self._data[start : self._cursor])

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector_u8(self) -> bytes:
        return self.take(self.u8())

    def vector_u16(self) -> bytes:
        return self.take(self.u16())

    def subreader(self, size: int, path: str) -> "Reader":
        start = self.offset
        return Reader(self.take(size), base_offset=start, path=path)

    def finish(self) -> None:
        if self.remaining:
            raise ParseError("trailing bytes", self.offset, self.path)
