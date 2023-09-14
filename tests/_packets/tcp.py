from .parse import from_hex

# s:win:Windows:7 or 8
WINDOWS_7_OR_8_EXACT = from_hex(
    "4500003032054000800635bcc0a80165adc22337dd6301bbdd0d6e360000000070022000a5b50000020405b401010402"
)

# s:win:Windows:7 or 8 (fuzzy TTL)
WINDOWS_7_OR_8_FUZZY_TTL = from_hex(
    "600000000020064020010470e5bfdead49572174e82c48872607f8b0400c0c03000000000000001af9c7001903a088300000000080022000da4700000204058c0103030801010402",
    6,
)

# g:win:Windows:NT kernel
WINDOWS_NT_KERNEL = from_hex(
    "4500003000ea40008006f5d9010101020101010104120035d1f8c116000000007002faf0ecd30000020405b401010402"
)

# s:win:Windows:XP
WINDOWS_XP = from_hex(
    "45000034434d40008006ddbb0affe4a98c635daf0f2c0050babd6b48000000008002ffff60a10000020404ec0103030201010402"
)

# s:unix:Linux:2.6.x
LINUX_26_SYN = from_hex(
    "4510003c41304000400674ddc0a8018cc0a801c2ddb80017dacf21d500000000a00216d071100000020405b40402080a002760e50000000001030307"
)

# s:unix:Linux:2.6.x
LINUX_26_SYN_ACK = from_hex(
    "450000340000400033066e098c635daf0affe4a900500f2cff15564ebabd6b49801216d0f3dc0000020405640101040201030309"
)

# s:unix:Linux:2.6.x
LINUX_26_SYN_ACK_ANOTHER = from_hex(
    "4500003c0000400038064e3b3f74f361c0a801030050e5c0a3c4809fe5943daba01216a04e070000020405b40402080a8d9d9dfa0017956501030305"
)

# s:unix:Linux:3.11 and newer
LINUX_311 = from_hex(
    "4510003c831b40004006150ac0a814464a7d831bd51d00196b7fc72d00000000a0027210a2b50000020405b40402080a0a9944360000000001030307"
)

# g:unix:Linux:2.2.x-3.x
LINUX_22_3 = from_hex(
    "4500003cd7ab400040064d0c0a0101020a01010184ff00b33c2fde2d00000000a00272100ee20000020405b40402080a077209860000000001030309"
)
