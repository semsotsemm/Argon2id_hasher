import struct
from dataclasses import dataclass
from constants import WORDS_IN_BLOCK


@dataclass
class Argon2Context:
    """Конфигурация параметров алгоритма"""
    time_cost: int      # Количество проходов
    memory_cost: int    # Объем памяти (кб)
    lanes: int          # Степень параллеизма
    hash_length: int

    def __post__init__(self):
        if self.memory_cost < 8 * self.lanes:
            raise ValueError("Значение параметра m недопустимо: память должна быть минимум в 8 раз больше степень параллеизма.")
        if self.lanes < 1:
            raise ValueError("Значение параметра p недопустимо: минимальное значение степени параллеизма — 1.")


class Block:
    """Минимальная ячейка памяти алгоритма."""
    __slots__ = ['v']

    def __init__(self):
        self.v: list[int] = [0] * WORDS_IN_BLOCK

    def xor_with(self, other: "Block") -> None:
        """Побитовое исключающее или."""
        for i in range(WORDS_IN_BLOCK):
            self.v[i] ^= other.v[i]

    def copy(self) -> "Block":
        new_block = Block()
        new_block.v = self.v.copy()
        return new_block

    def to_bytes(self) -> bytes:
        """Сериализация. Преобразует в непрерывный список байтов."""
        return struct.pack(f"<{WORDS_IN_BLOCK}Q", *self.v) # < - младший байт должен быть первым. Q - unsigned long long

    def from_bytes(self, data: bytes) -> None:
        """Десериализация. Преобразует в 64-битные числа"""
        if(len(data) !=  WORDS_IN_BLOCK):
            raise ValueError("Был передан ошибочный поток байтов: длинна данных должна быть %d байт." % WORDS_IN_BLOCK)
        self.v = list(struct.unpack(f"<{WORDS_IN_BLOCK}Q", data))
