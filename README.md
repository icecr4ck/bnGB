# Game Boy loader and architecture plugin for Binary Ninja
Author: **Hugo Porcher (icecr4ck)**

## Description

A Binary Ninja plugin to load Game Boy ROMs and disassemble Game Boy architecture bytecode (Sharp LR35902).

This plugin is based on the description of Game Boy CPU opcodes from [here](https://github.com/lmmendes/game-boy-opcodes).

## Game Boy characteristics

* CPU: 8-bit
* RAM size: 8KB
* Similar to Intel 8080 and 8085 as well as [Zilog Z80](https://en.wikipedia.org/wiki/Zilog_Z80) microprocessors
* ROM structure
	* 0-0x100: program executed when the Game Boy is powered up
	* 0x100-0x103: entrypoint
	* 0x104-0x133: scrolling Nintendo graphic (needs to remain unchanged)
	* 0x134-0x14f: ROM header
		* 0x134-0x142: ROM title in uppercase ASCII
		* 0x143: GB Color (0x80) or GB classic (0)
		* 0x144-0x145: Licensee code (new)
		* 0x146: GB (0) or Super GB (3)
		* 0x147: cartridge type
		* 0x148: ROM size (number of banks from 2 to 96)
		* 0x149: RAM size (nb of banks from 0 to 16)
		* 0x14a: japanese code (0) or not (1)
		* 0x14b: licensee code (old)
		* 0x14c: mask ROM version number
		* 0x14d: complement check
		* 0x14e-014f: checksum 

## Installation

Run the following command in your Binary Ninja plugins directory:
```bash
git clone https://github.com/icecr4ck/bnGB.git
```

## Minimum version

This plugin has only been tested on the following version of Binary Ninja:

* release - 1.2.1921

## References

* [Game Boy CPU manual](http://marc.rawer.de/Gameboy/Docs/GBCPUman.pdf)
* [GB opcodes](https://github.com/lmmendes/game-boy-opcodes)  
* [Using and writing Binary Ninja plugins](https://docs.binary.ninja/guide/plugins/index.html)
* [Gameboy ROM header](https://www.zophar.net/fileuploads/2/10597teazh/gbrom.txt)

## License

This plugin is released under a [MIT](LICENSE) license.
