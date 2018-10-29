import struct
import re
import json
import os
from binaryninja import *

# from https://gis.stackexchange.com/questions/130027/getting-a-plugin-path-using-python-in-qgis
def resolve(name, basepath=None):
    if not basepath:
      basepath = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(basepath, name)

class GB(Architecture):
    name = "GB"
    address_size = 2
    default_int_size = 1
    max_instr_length = 3
    regs = {
        'A': RegisterInfo('A', 1),
        'B': RegisterInfo('B', 1),
        'C': RegisterInfo('C', 1),
        'D': RegisterInfo('D', 1),
        'E': RegisterInfo('E', 1),
        'F': RegisterInfo('F', 1),
        'H': RegisterInfo('H', 1),
        'L': RegisterInfo('L', 1),
        'SP': RegisterInfo('SP', 2),
        'PC': RegisterInfo('PC', 2),
    }
    stack_pointer = 'sp'
    flags = ["Z","N","H","C"]
    flag_write_types = ["*", "CZN", "ZN"]
    flag_roles = {
        'Z': FlagRole.ZeroFlagRole,
        'N': FlagRole.NegativeSignFlagRole,
        'H': FlagRole.HalfCarryFlagRole,
        'C': FlagRole.CarryFlagRole,
    }
    flags_written_by_flag_write_type = {
        "*": ["C", "Z", "H", "N"],
        "CZN": ["C", "Z", "N"],
        "ZN": ["Z", "N"],
    }
    # game boy opcodes in json format from https://github.com/lmmendes/game-boy-opcodes
    with open(resolve("opcodes.json"),'rb') as f:
        opcodes = json.loads(f.read())["unprefixed"]

    def perform_get_instruction_info(self,data,addr):
        opcode = struct.unpack('<B', data[0])[0]
        # Get instruction size
        i_info = InstructionInfo()
        for k in opcodes.keys():
            if int(k,16) == opcode:
                op_info = opcodes[k]
                i_info.length = op_info['length']
        # Emulate jump instruction
        if op_info is not None:
            if op_info['mnemonic'] == 'JR':
                arg = struct.unpack('<B', data[1:2])[0]
                if opcode == 0x28 or opcode == 0x38:
                    i_info.add_branch(BranchType.TrueBranch, arg)
                    i_info.add_branch(BranchType.FalseBranch, addr+2)
                elif opcode == 0x20 or opcode == 0x30:
                    i_info.add_branch(BranchType.TrueBranch, addr+2)
                    i_info.add_branch(BranchType.FalseBranch, arg)
                else:
                    i_info.add_branch(BranchType.UnconditionalBranch, arg)
            elif op_info['mnemonic'] == 'JP':
                if opcode == 0xe9:
                    i_info.add_branch(BranchType.UnconditionalBranch, 0xdead)
                else:
                    arg = struct.unpack('<H', data[1:3])[0]
                    if opcode == 0xca or opcode == 0xda:
                        i_info.add_branch(BranchType.TrueBranch, arg)
                        i_info.add_branch(BranchType.FalseBranch, addr+3)
                    elif opcode == 0xc0 or opcode == 0xd0:
                        i_info.add_branch(BranchType.TrueBranch, addr+3)
                        i_info.add_branch(BranchType.FalseBranch, arg)
                    else:
                        _info.add_branch(BranchType.UnconditionalBranch, arg)
            elif op_info['mnemonic'] == 'RET':
                i_info.add_branch(BranchType.FunctionReturn)
            elif op_info['mnemonic'] == 'CALL':
                i_info.add_branch(BranchType.CallDestination, struct.unpack("<H", data[1:3])[0])
        return i_info

    def get_token(operand, data):
        if re.search(r'(d|r|a)8', operand) is not None:
            value = struct.unpack('<B', data[1])[0]
            if re.match(r'(d|r|a)8', operand) is not None:
                token = InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(value))
            else:
                token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(value))
        elif re.search(r'(d|r|a)16', operand) is not None:
            value = struct.unpack('<H', data[1:3])[0]
            if re.match(r'(d|r|a)16', operand) is not None:
                token = InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(value))
            else:
                token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(value))
        elif re.search(r'A|B|C|D|E|F|H|L|(SP)|(PC)', operand) is not None:
            if re.match(r'A|B|C|D|E|F|H|L|(SP)|(PC)', operand) is not None:
                token = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand)
            else:
                token = InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, operand)
        else:
            token = InstructionTextToken(InstructionTextTokenType.RegisterToken, operand)
        return token

    def perform_get_instruction_text(self, data, addr):
        tokens = []
        opcode = struct.unpack('<B', data[0])[0]
        for k in opcodes.keys():
            if int(k,16) == opcode:
                op_info = opcodes[k]
        if op_info is not None:
            tokens.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, op_info['mnemonic']))
            inst_size = 1
            if 'operand1' in op_info:
                tokens.append(get_token(op_info['operand1'], data))
                inst_size = 2
                if 'operand2' in op_info:
                    tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,', '))
                    tokens.append(get_token(op_info['operand2'], data))
                    inst_size = 3
        return tokens, inst_size

    def perform_get_instruction_low_level_il(self, data, addr, il):
        return None

class GBView(BinaryView):
    name = "GB"
    long_name = "Game Boy ROM"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
        self.platform = Architecture['GB'].standalone_platform

    def init(self):
        try:
            hdr = self.parent_view.read(0x134, 0x150)
            self.rom_banks = struct.unpack("B", hdr[20])[0]
            self.ram_banks = struct.unpack("B", hdr[21])[0]
            self.rom_title = hdr[0:14]
            return True
        except:
            log_error(traceback.format_exc())
            return False
    
    def perform_is_executable(self):
	return True

    def perform_get_entry_point(self):
	return 0x100

GB.register()
