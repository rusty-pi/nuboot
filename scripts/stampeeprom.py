#!/usr/bin/env python3
"""Put the time of an EEPROM update in a copy of an EEPROM image, in the flash's
last 8 bytes as the stock bootloader does after it writes an update: the time
and its complement. For the scenario that boots after the update.

    stampeeprom.py PIEEPROM OUT TIME
"""

import struct
import sys

if len(sys.argv) != 4:
    sys.exit(__doc__)
image = bytearray(open(sys.argv[1], "rb").read())
stamp = int(sys.argv[3], 0)
image[-8:] = struct.pack("<II", ~stamp & 0xFFFFFFFF, stamp)
open(sys.argv[2], "wb").write(image)
