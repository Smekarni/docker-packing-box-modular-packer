import argparse
import os
import lief
import importlib
import pkgutil
from packer import Packer

PLUGIN_REGISTRY = {}

def load_plugins():
	"""Dynamically load plugins from the "plugins" directory
	"""
	plugin_dir = os.path.join(os.path.dirname(__file__), "plugins")
	for _, module_name, _ in pkgutil.iter_modules([plugin_dir]):
		module = importlib.import_module(f"plugins.{module_name}")
		for attr_name in dir(module):
			attr = getattr(module, attr_name)
			if isinstance(attr, type) and attr_name.endswith("Plugin"):
				plugin_type = attr_name.replace("Plugin", "").lower()
				PLUGIN_REGISTRY[plugin_type] = attr

class CoreEngine:
	def __init__(self, file_path):
		self.input_file_path = file_path
		self.plugins = []
		self.file = None
		self.file_format = None
		self.arch = None
		self.raw = b''

	def parse_plugins(self, plugins):
		"""Parse the plugins specified in the command line:
			Args:
				- plugins: str (ie: xor:0xAA)
		"""
		try:
			for plugin in plugins.split(","):
				plugin_type, _, params = plugin.partition(":")

				plugin_class = PLUGIN_REGISTRY.get(plugin_type)
				if not plugin_class:
					raise ValueError(f"Unknown plugin: {plugin_type}")

				self.plugins.append(plugin_class(params))
		except AttributeError:
			print("No plugin provided using default only...")

	def execute(self):
		"""Execute plugins on the input file.
		"""
		self.parse_file()
		if not self.file:
			print("Failed to parse input file. Aborting.")
			return

		# Run plugins
		packer = Packer(self.raw, self.file, self.arch, self.file_format)
		packed_file = packer.main(self.plugins)

	def parse_file(self):
		"""Parse an executable file using LIEF.
		"""
		with open(self.input_file_path, "rb") as f:
			self.raw = f.read()
		try:
			self.file = lief.parse(self.input_file_path)
			file_format = self.file.format.value
			if file_format == 1:
				self.file_format = "elf"
			elif file_format == 2:
				self.file_format = "pe"
				self.arch = "x86" if self.file.abstract.header.is_32 else "x64"
			elif file_format == 3:
				self.file_format = "macho"
			elif file_format == 4:
				self.file_format == "oat"
			print(f"Successfully parsed executable file: {self.input_file_path}")
		except Exception as e: # Need to trigger specific exception
			print(f"Failed to parse executable file: {e}")
			return

def main():
	load_plugins()

	parser = argparse.ArgumentParser(description="Modular Packer with Plugins")
	parser.add_argument("--input", "-i", required=True, help="Input file")
	parser.add_argument("--plugins", "-p", help="Comma-separated list of plugins")
	args = parser.parse_args()

	engine = CoreEngine(args.input)
	engine.parse_plugins(args.plugins)
	engine.execute()


if __name__ == "__main__":
	main()
	#exemple commande pour run le code
	#python packer.py --input dist/generate_exe.exe --output packed_generate_exe.exe --plugins compression_plugin

