import os
import struct
import hashlib
import random
import string
from dotenv import load_dotenv


from auxilitry_structures import Argon2Context, Block
from constants import SYNC_POINT


load_dotenv()

PASSWORD = os.getenv("ARGON_PASSWORD")
SALT = os.getenv("ARGON_SALT")

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
        generated_hash = hashlib.blake2b(digest_size=64)
        generated_hash.update(struct.pack('<6I', self.context.lanes, self.context.hash_length, self.context.memory_cost, self.context.time_cost, 19, 2))

        generated_hash.update(struct.pack('<I', len(password)))
        generated_hash.update(password)

        generated_hash.update(struct.pack('<I', len(salt)))
        generated_hash.update(salt)

        generated_hash.update(struct.pack('<2I', 0, 0))
        return generated_hash.digest()


    def _fill_first_block(self, h0: bytes) -> None:
        for i in range(self.context.lanes):
            block0 = h0 + struct.pack('<2I', 0, i)
            self.memory[i][0].from_bytes(self._blake2b_long(block0, 1024))

            block1 = h0 + struct.pack('<2I', 1, i)
            self.memory[i][1].from_bytes(self._blake2b_long(block1, 1024))


    def _process_segment(self, pass_num:int, slice_num:int, lane_num: int) -> None:
        segment_length = self.lane_length // SYNC_POINT

        start_index = slice_num * segment_length
        end_index = start_index + segment_length

        if pass_num == 0 and slice_num == 0:
            start_index = 2

        for current_index in range(start_index, end_index):
            if current_index == 0:
                prev_index = self.lane_length - 1
            else:
                prev_index = current_index - 1

            prev_block = self.memory[lane_num][prev_index]

            ref_lane, ref_index = self._compute_ref_index(
                pass_num, slice_num, lane_num, current_index, prev_block
            )
            ref_block = self.memory[ref_lane][ref_index]

            current_block = self.memory[lane_num][current_index]
            self._compress_block(current_block, prev_block, ref_block, pass_num)


    def _compute_ref_index(self,  pass_num: int,  slice_num:int, lane_num:int, current_index:int, prev_block:Block) -> tuple[int, int]:
        pseudo_rand = prev_block.v[0]

        ref_lane = pseudo_rand % self.context.lanes

        ref_index = (pseudo_rand >> 32) % self.lane_length

        if ref_lane == lane_num and ref_index == current_index:
            ref_index = (ref_index - 1) % self.lane_length

        return ref_lane, ref_index


    def _compress_block(self,  current_block: Block, prev_block: Block, ref_block: Block, pass_num:int) -> None:
        for i in range(128):
            current_block.v[i] = prev_block.v[i] ^ ref_block.v[i]

        for i in range(128):
            x = current_block.v[i]

            x ^= (x >> 32) ^ (x << 16)

            current_block.v[i] = x & 0xFFFFFFFFFFFFFFFF
        if pass_num == 0:
            pass


    def _finalize(self) -> str:
        final_block = self.memory[0][self.lane_length - 1].copy()

        for i in range(1, self.context.lanes):
            final_block.xor_with(self.memory[i][self.lane_length - 1])

        final_bytes = final_block.to_bytes()
        final_hash_bytes = self._blake2b_long(final_bytes, self.context.hash_length)

        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        digits = string.digits
        specials = "$&#%^*!@_"

        rng = random.Random(final_hash_bytes)

        password_chars = [
            rng.choice(upper),
            rng.choice(lower),
            rng.choice(digits),
            rng.choice(specials)
        ]

        all_allowed_chars = upper + lower + digits + specials
        password_chars += rng.choices(all_allowed_chars, k=8)

        rng.shuffle(password_chars)

        return "".join(password_chars)


    def _blake2b_long(self, input_data:bytes, output_len:int) -> bytes:
        length_bytes  = struct.pack("<I", output_len)

        if(output_len <= 64):
            return hashlib.blake2b(length_bytes + input_data, digest_size=output_len).digest()

        out = bytearray()
        v_i = hashlib.blake2b(length_bytes + input_data, digest_size = 64).digest()
        out.extend(v_i[:32])

        while(len(out) + 64 <  output_len):
            v_i = hashlib.blake2b(v_i,digest_size=64).digest()
            out.extend(v_i[:32])

        v_i = hashlib.blake2b(v_i,digest_size=output_len - len(out)).digest()
        out.extend(v_i)

        return bytes(out)


if __name__ == "__main__":
    config = Argon2Context(time_cost=2, memory_cost=1024, lanes=1, hash_length=9)
    hasher = Argon2id(config)
    result = hasher.hash(password=PASSWORD.encode('utf-8'), salt=SALT.encode('utf-8'))
    print(result)