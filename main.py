from auxilitry_structures import Argon2Context, Block
from constants import SYNC_POINT

class Argon2id:
    def __init__(self, context: Argon2Context):
        self.context: Argon2Context = context

        self.lane_length = self.context.memory_cost // self.context.lanes
        self.memory_blocks = self.lane_length * self.context.lanes

        self.memory: list[list[Block]] = [
            [Block() for i in range(self.lane_length)]
            for j in range(self.context.lanes)
        ]


    def hash(self, password:bytes, salt:bytes) -> str:
        initial_hash = self._compute_initial_hash(password, salt)

        self._fill_first_block(initial_hash)

        for pass_num in range(self.context.time_cost):
            for slice_num in range(SYNC_POINT):
                for lane_num in range(self.context.lanes):
                    self._process_segment(pass_num = pass_num, slice_num = slice_num, lane_num = lane_num)

        return self._finalize()



    def _compute_initial_hash(self, password:bytes, salt:bytes) -> bytes:
        # todo: Сделать BLAKE2b
        return b'\x00' * 64


    def _fill_first_block(self, h0: bytes) -> None:
        # todo: Сделать генерацию 1 и 2 столбца i строки
        pass


    def _process_segment(self, pass_num:int, slice_num:int, lane_num: int) -> None:
        # todo: Сделать адресацию блоков и сжатие
        pass


    def _finalize(self) -> str:
        # todo:  Xor и вызова hex-строки
        return 'fake hash'


if __name__ == "__main__":
    config = Argon2Context(time_cost=2, memory_cost=1024, lanes=1, hash_length=12)
    hasher = Argon2id(config)
    result = hasher.hash(password=b'hello world', salt=b'hello world')
    print(result)