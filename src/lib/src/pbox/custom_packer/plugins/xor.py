import re

class XorPlugin:
	def __init__(self, args):
		pattern = r"^0x[a-fA-F0-9]{2}$"
		if re.match(pattern, args):
			self.key = args
		else:
			print("XorPlugin: Incorrect parameter")
			print("Please provide a key in the form: 0x[0-9A-F]{2}")
			print("Example: xor:0x5F")
			exit()

	def run(self, data):
		data = bytes([b ^ int(self.key, 16) for b in data])
		stub = """
DWORD oldProtect;
VirtualProtect(src, size, PAGE_READWRITE, &oldProtect);

DWORD key = KEY;
for(DWORD i=0; i<size; ++i) {
	src[i] = src[i] ^ key;
}
		""".replace("KEY", self.key)
		return (data, stub)