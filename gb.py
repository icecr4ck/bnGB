import struct
import re

from .opcodes_fetcher import opcodes

from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, FlagRole, BranchType

class GB(Architecture):
    name = "GB"
    address_size = 2
    default_int_size = 1
    max_instr_length = 3
    regs = {
        'a': RegisterInfo('a', 1),
        'b': RegisterInfo('b', 1),
        'c': RegisterInfo('c', 1),
        'd': RegisterInfo('d', 1),
        'e': RegisterInfo('e', 1),
        'f': RegisterInfo('f', 1),
        'h': RegisterInfo('h', 1),
        'l': RegisterInfo('l', 1),
        'af': RegisterInfo('af', 2),
        'bc': RegisterInfo('bc', 2),
        'cb': RegisterInfo('cb', 2),
        'de': RegisterInfo('de', 2),
        'hl': RegisterInfo('hl', 2),
        'sp': RegisterInfo('sp', 2),
        'pc': RegisterInfo('pc', 2),
    }
    stack_pointer = 'sp'
    flags = ["z","n","h","c"]
    flag_write_types = ["*", "czn", "zn"]
    flag_roles = {
        'z': FlagRole.ZeroFlagRole,
        'n': FlagRole.NegativeSignFlagRole,
        'h': FlagRole.HalfCarryFlagRole,
        'c': FlagRole.CarryFlagRole,
    }
    flags_written_by_flag_write_type = {
        "*": ["c", "z", "h", "n"],
        "czn": ["c", "z", "n"],
        "zn": ["z", "n"],
    }

    def decode_operand(self, operand):
        if operand in self.regs.keys():
            return operand
        return None
        
    def decode_instruction(self, data, addr):
        if len(data) < 1:
            return None, None, None, None, None
        opcode = data[0]
        try:
            info = opcodes[hex(opcode)]
        except KeyError:
            return None, None, None, None, None
        instr = info['mnemonic']
        length = info['length']
        operands = []
        if 'operand1' in info:
            operands.append(info['operand1'].lower())
        if 'operand2' in info:
            operands.append(info['operand2'].lower())
        flags = [f.lower() for f in info['flags']]
        if length == 2:
            value = data[1]
        elif length == 3:
            value = struct.unpack('<H', data[1:3])[0]
        else:
            value = None
        return instr, length, operands, flags, value

    def perform_get_instruction_info(self, data, addr):
        instr, length, operands, flags, value = self.decode_instruction(data, addr)
        if instr is None:
            return None
        result = InstructionInfo()
        result.length = length
        opcode = data[0]
        if instr == 'JR':
            arg = data[1]
            dest = arg if arg < 128 else (256-arg) * (-1)
            if opcode == 0x28 or opcode == 0x38:
                result.add_branch(BranchType.TrueBranch, addr+2+dest)
                result.add_branch(BranchType.FalseBranch, addr+2)
            elif opcode == 0x20 or opcode == 0x30:
                result.add_branch(BranchType.TrueBranch, addr+2)
                result.add_branch(BranchType.FalseBranch, addr+2+dest)
            else:
                result.add_branch(BranchType.UnconditionalBranch, addr+2+dest)
        elif instr == 'JP':
            if opcode == 0xe9:
                result.add_branch(BranchType.UnconditionalBranch, 0xdead)
            else:
                arg = struct.unpack('<H', data[1:3])[0]
                if opcode == 0xca or opcode == 0xda:
                    result.add_branch(BranchType.TrueBranch, arg)
                    result.add_branch(BranchType.FalseBranch, addr+3)
                elif opcode == 0xc2 or opcode == 0xd2:
                    result.add_branch(BranchType.TrueBranch, addr+3)
                    result.add_branch(BranchType.FalseBranch, arg)
                else:
                    result.add_branch(BranchType.UnconditionalBranch, arg)
        elif instr == 'RET':
            result.add_branch(BranchType.FunctionReturn)
        elif instr == 'CALL':
            result.add_branch(BranchType.CallDestination, struct.unpack("<H", data[1:3])[0])
        return result

    def get_token(self, mnemonic, operand, data):
        if re.search(r'(d|r|a)8', operand) is not None:
            value = data[1]
            if re.match(r'(d|r|a)8', operand) is not None:
                token = InstructionTextToken(InstructionTextTokenType.IntegerToken, "0x%.2x" % value, value)
            elif re.match(r'\(a8\)', operand) is not None:
                token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "0xff%.2x" % value, value|0xff00)
            else:
                token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "0x%.4x" % value, value)
        elif re.search(r'(d|r|a)16', operand) is not None:
            value = struct.unpack('<H', data[1:3])[0]
            if re.match(r'(d|r|a)16', operand) is not None:
                if mnemonic == "CALL":
                    token = InstructionTextToken(InstructionTextTokenType.DataSymbolToken, "sub_%x" % value, value)
                elif re.match(r'\(a16\)', operand) is not None:
                    token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "0x%.4x" % value, value)
                else:
                    token = InstructionTextToken(InstructionTextTokenType.IntegerToken, "0x%.4x" % value, value)
            else:
                token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "0x%.4x" % value, value)
        elif re.search(r'A|B|C|D|E|F|H|L|(SP)|(PC)', operand) is not None:
            if re.match(r'A|B|C|D|E|F|H|L|(SP)|(PC)', operand) is not None:
                token = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand.lower())
            else:
                token = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand.lower())
        else:
            token = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand.lower())
        return token

    def perform_get_instruction_text(self, data, addr):
        instr, length, operands, flags, value = self.decode_instruction(data, addr)
        tokens = []
        opcode = data[0]
        if instr is None:
            return None
        tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, instr.lower()))
        if len(operands) >= 1:
            tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, ''.rjust(8 - len(instr))))
            tokens.append(self.get_token(instr, operands[0], data))
            if len(operands) == 2 :
                tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,', '))
                tokens.append(self.get_token(instr, operands[1], data))
        return tokens, length

    def perform_get_instruction_low_level_il(self, data, addr, il):
        return None
