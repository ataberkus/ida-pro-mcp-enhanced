"""
Vendored sigmaker core — unique signature generation engine.

Original: sigmaker.py - IDA Python Signature Maker
https://github.com/mahmoudimus/ida-sigmaker
by @mahmoudimus (Mahmoud Abdelkader)

This is a stripped-down, self-contained copy of the sigmaker library,
synced with upstream v1.8.0. Only the pieces api_sigmaker.py uses are kept:
growing the shortest unique signature from an address, operand wildcarding
via WildcardPolicy, and the output formatters. Uniqueness is checked with
idaapi.bin_search, bailing at the second match.

It relies only on idaapi and the standard library. The interactive layers
(IDA Forms, the plugin class, wait boxes, clipboard) are intentionally NOT
vendored: this engine runs inside an MCP server, where modal UI is never
appropriate.

MIT License

Copyright (c) 2024 Mahmoud Abdelkader (@mahmoudimus)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from __future__ import annotations

import contextvars
import dataclasses
import enum
import typing

import idaapi
import ida_funcs

__author__ = "mahmoudimus"
__version__ = "1.8.0"


WILDCARD_POLICY_CTX: contextvars.ContextVar["WildcardPolicy"] = contextvars.ContextVar(
    "wildcard_policy"
)


def _user_canceled() -> bool:
    """Headless-safe wrapper around IDA's cancellation predicate.

    IDA exposes the British spelling ``user_cancelled``. In a headless idalib
    context the function still exists and simply returns False, so polling it
    is harmless; guard anyway so the engine never hard-depends on it.
    """
    fn = getattr(idaapi, "user_cancelled", None)
    if fn is None:
        return False
    try:
        return bool(fn())
    except Exception:
        return False


class Unexpected(Exception):
    """Exception type used throughout the module to indicate unexpected errors."""


def is_address_marked_as_code(ea: int) -> bool:
    return idaapi.is_code(idaapi.get_flags(ea))


@dataclasses.dataclass
class SigMakerConfig:
    output_format: SignatureType
    wildcard_operands: bool
    continue_outside_of_function: bool
    wildcard_optimized: bool
    ask_longer_signature: bool = True
    max_single_signature_length: int = 100


@dataclasses.dataclass(slots=True, frozen=True, repr=False)
class Match:
    address: int

    def __repr__(self) -> str:
        return f"Match(address={hex(self.address)})"

    def __str__(self) -> str:
        return hex(self.address)

    def __int__(self) -> int:
        return self.address

    __index__ = __int__


class SignatureType(enum.Enum):
    IDA = "ida"
    x64Dbg = "x64dbg"
    Mask = "mask"
    BitMask = "bitmask"


class SignatureByte(typing.NamedTuple):
    value: int
    is_wildcard: bool


class Signature(list[SignatureByte]):
    def add_byte_to_signature(self, address: int, is_wildcard: bool) -> None:
        byte_value = idaapi.get_byte(address)
        self.append(SignatureByte(byte_value, is_wildcard))

    def add_bytes_to_signature(
        self, address: int, count: int, is_wildcard: bool
    ) -> None:
        bytes_data = idaapi.get_bytes(address, count)
        if bytes_data:
            self.extend(SignatureByte(b, is_wildcard) for b in bytes_data)

    def trim_signature(self) -> None:
        n = len(self)
        while n > 0 and self[n - 1].is_wildcard:
            n -= 1
        del self[n:]

    def __str__(self) -> str:
        return self.__format__("")

    def __format__(self, format_spec: str) -> str:
        spec = format_spec.lower()
        try:
            formatter = FORMATTER_MAP[SignatureType(spec)]
        except KeyError:
            raise ValueError(
                f"Unknown format code '{format_spec}' for object of type 'Signature'"
            )
        return formatter.format(self)


class SignatureFormatter(typing.Protocol):
    def format(self, signature: "Signature") -> str: ...


@dataclasses.dataclass(frozen=True, slots=True)
class IdaFormatter:
    wildcard_byte: str = "?"

    def format(self, signature: "Signature") -> str:
        parts = []
        for byte in signature:
            if byte.is_wildcard:
                parts.append(self.wildcard_byte)
            else:
                parts.append(f"{byte.value:02X}")
        return " ".join(parts)


@dataclasses.dataclass(frozen=True, slots=True)
class X64DbgFormatter(IdaFormatter):
    wildcard_byte: str = "??"


@dataclasses.dataclass(frozen=True, slots=True)
class MaskedBytesFormatter:
    wildcard_byte: str = "\\x00"
    mask: str = "x"
    wildcard_mask: str = "?"

    @staticmethod
    def build_signature_parts(
        signature: "Signature",
        byte_format: str,
        wildcard_byte: str,
        mask_char: str,
        wildcard_mask_char: str,
    ) -> tuple[list[str], list[str]]:
        pattern_parts = []
        mask_parts = []
        for byte in signature:
            if byte.is_wildcard:
                pattern_parts.append(wildcard_byte)
                mask_parts.append(wildcard_mask_char)
            else:
                pattern_parts.append(byte_format.format(byte.value))
                mask_parts.append(mask_char)
        return pattern_parts, mask_parts

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = self.build_signature_parts(
            signature,
            "\\x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        return "".join(pattern_parts) + " " + "".join(mask_parts)


@dataclasses.dataclass(frozen=True, slots=True)
class ByteArrayBitmaskFormatter:
    wildcard_byte: str = "0x00"
    mask: str = "1"
    wildcard_mask: str = "0"

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = MaskedBytesFormatter.build_signature_parts(
            signature,
            "0x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        pattern_str = ", ".join(pattern_parts)
        mask_str = "".join(mask_parts)[::-1]
        return f"{pattern_str} 0b{mask_str}"


FORMATTER_MAP: typing.Dict[SignatureType, SignatureFormatter] = {
    SignatureType.IDA: IdaFormatter(),
    SignatureType.x64Dbg: X64DbgFormatter(),
    SignatureType.Mask: MaskedBytesFormatter(),
    SignatureType.BitMask: ByteArrayBitmaskFormatter(),
}


@dataclasses.dataclass(slots=True, frozen=True)
class WildcardPolicy:
    allowed_types: frozenset[int]
    _ctx = WILDCARD_POLICY_CTX

    class BaseKind(enum.IntEnum):
        MEM = idaapi.o_mem
        PHRASE = idaapi.o_phrase
        DISPL = idaapi.o_displ
        IMM = idaapi.o_imm
        FAR = idaapi.o_far
        NEAR = idaapi.o_near

    class X86Kind(enum.IntEnum):
        TRREG = idaapi.o_idpspec0
        DBREG = idaapi.o_idpspec1
        CRREG = idaapi.o_idpspec2
        FPREG = idaapi.o_idpspec3
        MMX = idaapi.o_idpspec4
        XMM = idaapi.o_idpspec5
        YMM = idaapi.o_idpspec5 + 1
        ZMM = idaapi.o_idpspec5 + 2
        KREG = idaapi.o_idpspec5 + 3

    class ARMKind(enum.IntEnum):
        REGLIST = idaapi.o_idpspec1
        CREGLIST = idaapi.o_idpspec2
        CREG = idaapi.o_idpspec3
        FPREGLIST = idaapi.o_idpspec4
        TEXT = idaapi.o_idpspec5
        COND = idaapi.o_idpspec5 + 1

    class PPCKind(enum.IntEnum):
        SPR = idaapi.o_idpspec0
        TWOFPR = idaapi.o_idpspec1
        SHMBME = idaapi.o_idpspec2
        CRF = idaapi.o_idpspec3
        CRB = idaapi.o_idpspec4
        DCR = idaapi.o_idpspec5

    @classmethod
    def for_x86(cls) -> "WildcardPolicy":
        # Exclude BaseKind.IMM. An immediate like the 0x13371338 in
        # `mov rcx, 0x13371338` is a literal value baked into the
        # instruction encoding; it does not shift between binary builds,
        # so wildcarding it only removes bytes that would have made the
        # signature unique. MEM/FAR/NEAR still get wildcarded because
        # those operands DO encode addresses that move between builds.
        x86_base = frozenset(cls.BaseKind) - {cls.BaseKind.IMM}
        return cls(x86_base | frozenset(cls.X86Kind))

    @classmethod
    def detect_from_processor(cls) -> "WildcardPolicy":
        arch = idaapi.ph_get_id()
        if arch == idaapi.PLFM_386:
            return cls.for_x86()
        base = frozenset(cls.BaseKind)
        if arch == idaapi.PLFM_ARM:
            return cls(base | frozenset(cls.ARMKind))
        if arch == idaapi.PLFM_MIPS:
            return cls(frozenset({cls.BaseKind.MEM, cls.BaseKind.FAR, cls.BaseKind.NEAR}))
        if arch == idaapi.PLFM_PPC:
            return cls(base | frozenset(cls.PPCKind))
        return cls(base)

    def allows_type(self, op_type: int) -> bool:
        return op_type in self.allowed_types

    @classmethod
    def current(cls) -> "WildcardPolicy":
        policy = cls._ctx.get(cls.detect_from_processor())
        cls._ctx.set(policy)
        return policy


@dataclasses.dataclass(slots=True, frozen=True)
class GeneratedSignature:
    """Result container for signature generation operations."""

    signature: Signature
    address: Match | None = None


class OperandProcessor:
    def __init__(self):
        self._is_arm = self._check_is_arm()

    @staticmethod
    def _check_is_arm() -> bool:
        return idaapi.ph_get_id() == idaapi.PLFM_ARM

    def _get_operand_offset_arm(
        self, ins: idaapi.insn_t, off: typing.List[int], length: typing.List[int]
    ) -> bool:
        policy = WildcardPolicy.current()
        for op in ins:
            if op.type in policy.allowed_types:
                off[0] = op.offb
                length[0] = 3 if ins.size == 4 else (7 if ins.size == 8 else 0)
                return True
        return False

    def get_operand(
        self,
        ins: idaapi.insn_t,
        off: typing.List[int],
        length: typing.List[int],
        wildcard_optimized: bool,
    ) -> bool:
        policy = WildcardPolicy.current()
        if self._is_arm:
            return self._get_operand_offset_arm(ins, off, length)
        for op in ins:
            if op.type == idaapi.o_void:
                continue
            if not policy.allows_type(op.type):
                continue
            if op.offb == 0 and not wildcard_optimized:
                continue
            off[0] = op.offb
            length[0] = ins.size - op.offb
            return True
        return False


class InstructionProcessor:
    def __init__(self, operand_processor: OperandProcessor):
        self.operand_processor = operand_processor

    def append_instruction_to_sig(
        self,
        sig: Signature,
        ea: int,
        ins: idaapi.insn_t,
        wildcard_operands: bool,
        wildcard_optimized: bool,
    ) -> None:
        if not wildcard_operands:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        off, length = [0], [0]
        has_operand = self.operand_processor.get_operand(
            ins, off, length, wildcard_optimized
        )
        if not has_operand or length[0] <= 0:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        if off[0] > 0:
            sig.add_bytes_to_signature(ea, off[0], is_wildcard=False)

        sig.add_bytes_to_signature(ea + off[0], length[0], is_wildcard=True)

        remaining_len = ins.size - (off[0] + length[0])
        if remaining_len > 0:
            sig.add_bytes_to_signature(
                ea + off[0] + length[0], remaining_len, is_wildcard=False
            )


@dataclasses.dataclass(slots=True)
class InstructionWalker:
    start_ea: int
    end_ea: int = idaapi.BADADDR

    cursor: int = dataclasses.field(init=False)
    _instruction: idaapi.insn_t = dataclasses.field(
        init=False, repr=False, default_factory=idaapi.insn_t
    )

    def __post_init__(self):
        if self.start_ea == idaapi.BADADDR:
            raise ValueError("Invalid start address for InstructionWalker")
        self.cursor = self.start_ea

    def __iter__(self):
        self.cursor = self.start_ea
        return self

    def __next__(self) -> tuple[int, idaapi.insn_t, int]:
        if self.end_ea != idaapi.BADADDR and self.cursor >= self.end_ea:
            raise StopIteration

        current_instruction_ea = self.cursor
        ins_len = idaapi.decode_insn(self._instruction, current_instruction_ea)

        if ins_len <= 0:
            raise StopIteration

        self.cursor += ins_len

        return current_instruction_ea, self._instruction, ins_len


class UniqueSignatureGenerator:
    def __init__(self, processor: InstructionProcessor):
        self.processor = processor

    def generate(self, ea: int, cfg: SigMakerConfig) -> Signature:
        if not is_address_marked_as_code(ea):
            raise Unexpected("Cannot create code signature for data")

        sig = Signature()
        start_fn = ida_funcs.get_func(ea)
        bytes_since_last_check = 0

        for cur_ea, ins, ins_len in InstructionWalker(ea):
            if bytes_since_last_check > cfg.max_single_signature_length:
                if not cfg.ask_longer_signature:
                    raise Unexpected("Signature not unique within length constraints")
                bytes_since_last_check = 0

            if (
                not cfg.continue_outside_of_function
                and start_fn
                and cur_ea >= start_fn.end_ea
            ):
                raise Unexpected("Signature left function scope without being unique")

            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )
            bytes_since_last_check += ins_len

            if SignatureSearcher.is_unique(f"{sig:ida}"):
                sig.trim_signature()
                return sig

        raise Unexpected("Signature not unique (reached end of analysis)")


@dataclasses.dataclass(slots=True)
class SignatureMaker:
    _operand_processor: OperandProcessor = dataclasses.field(
        default_factory=OperandProcessor
    )
    _unique_generator: UniqueSignatureGenerator = dataclasses.field(init=False)

    def __post_init__(self):
        self._unique_generator = UniqueSignatureGenerator(
            InstructionProcessor(self._operand_processor)
        )

    def make_signature(self, ea: int | Match, cfg: SigMakerConfig) -> GeneratedSignature:
        start_ea = int(ea)
        if start_ea == idaapi.BADADDR:
            raise Unexpected("Invalid start address")
        sig = self._unique_generator.generate(start_ea, cfg)
        return GeneratedSignature(sig, Match(start_ea))


class SignatureSearcher:
    @staticmethod
    def find_all(ida_signature: str, skip_more_than_one: bool = False) -> list[Match]:
        from .compat import inf_get_min_ea, inf_get_max_ea
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        ea = inf_get_min_ea()
        max_ea = inf_get_max_ea()
        _bin_search = getattr(idaapi, "bin_search", None) or getattr(
            idaapi, "bin_search3"
        )
        flags = idaapi.BIN_SEARCH_NOCASE | idaapi.BIN_SEARCH_FORWARD
        while True:
            if _user_canceled():
                break
            hit, _ = _bin_search(ea, max_ea, binary, flags)
            if hit == idaapi.BADADDR:
                break
            out.append(Match(hit))
            # is_unique only needs to know if there is more than one match;
            # bail at 2 instead of enumerating every match in the database.
            if skip_more_than_one and len(out) > 1:
                break
            ea = hit + 1
        return out

    @classmethod
    def is_unique(cls, ida_signature: str) -> bool:
        """Return True iff the signature matches exactly one location.

        Bails at the second match. Enumerating all matches of a short, common
        signature is catastrophic on a large binary, and uniqueness only
        depends on whether the count is 0, 1, or 2+.
        """
        matches = cls.find_all(ida_signature, skip_more_than_one=True)
        return len(matches) == 1
