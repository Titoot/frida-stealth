import os
import re
import pathlib
import argparse

# ================= DEFAULT CONFIGURATION =================
DEFAULT_PREFIX = "Banana"
DEFAULT_PORT_CONTROL = "27043"
DEFAULT_PORT_CLUSTER = "27053"

# Target specific subprojects
TARGET_SUBPROJECTS = ["frida-core", "frida-gum"]

# Directories to skip entirely
SKIP_DIRS = {
    ".git", ".github", "releng", "tests", 
    "termux-elf-cleaner", "subprojects", "tools" 
}

def get_replacements(config):
    """Returns list of (Regex Pattern, Replacement String) based on config."""
    
    name = config['name']                 # e.g. "Banana"
    name_lower = config['name_lower']     # e.g. "banana"
    thread_prefix = config['thread_prefix'] # e.g. "banana-"
    bundle_id = config['bundle_id']       # e.g. "re.banana"
    port_control = config['port_control']
    port_cluster = config['port_cluster']

    return [
        # --- Thread Names & Pipes ---
        (r'"frida-main-loop"', f'"{thread_prefix}main-loop"'),
        (r'"frida-server-main-loop"', f'"{thread_prefix}server-main-loop"'),
        (r'"frida-gadget"', f'"{thread_prefix}gadget"'),
        (r'"gum-js-loop"', f'"{thread_prefix}js-loop"'),
        (r'"gmain"', f'"{thread_prefix}gmain"'), 
        (r'"frida-agent-container"', f'"{thread_prefix}container"'),
        
        # --- Protocol / Network ---
        (r'"frida:rpc"', f'"{name_lower}:rpc"'), 
        (r'27042', port_control),
        (r'27052', port_cluster),
        
        # --- User Agents / Headers ---
        (r'"Frida"', f'"{name}"'), 
        (r'"Frida/"', f'"{name}/"'),
        
        # --- SELinux / Files ---
        (r'"frida_file"', f'"{name_lower}_file"'),
        (r'"frida_memfd"', f'"{name_lower}_memfd"'),
        (r'"re.frida.server"', f'"{bundle_id}.server"'),
        (r'"re.frida.Gadget"', f'"{bundle_id}.Gadget"'),
        
        # --- Linux/Injector Vala Specifics ---
        (r'"frida-agent-"', f'"{thread_prefix}agent-"'),
        (r'"frida-helper-"', f'"{thread_prefix}helper-"'),
        (r'/frida-', f'/{thread_prefix}'),

        # --- Base64 RPC Hiding (Specific to lib/base/rpc.vala) ---
        # Note: We replace the string literal with the Base64 decode call
        (r'\.add_string_value \("frida:rpc"\)', r'.add_string_value ((string) GLib.Base64.decode("ZnJpZGE6cnBj="))'),
        (r'if \(json.index_of \("\"frida:rpc\""\) == -1\)', r'if (json.index_of ((string) GLib.Base64.decode("ImZyaWRhOnJwYyI=")) == -1)'),
        (r'if \(type == null \|\| type != "frida:rpc"\)', r'if (type == null || type != (string) GLib.Base64.decode("ZnJpZGE6cnBj="))'),
        
        # --- FIFO Obfuscation (Specific to frida-helper-backend-glue.c) ---
        (r'g_strdup_printf \("%s/linjector-%u", self->temp_path, self->id\);', r'g_strdup_printf ("%s/%p%u", self->temp_path, self, self->id);')
    ]

def process_file(file_path, replacements, dry_run=False):
    """Iterates line-by-line to find matches and modify file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        new_lines = []
        file_changed = False
        
        for i, line in enumerate(lines):
            original_line = line
            current_line = line
            
            # Apply all replacements to this line
            for pattern, replacement in replacements:
                if re.search(pattern, current_line):
                    current_line = re.sub(pattern, replacement, current_line)
            
            # Check if line changed
            if current_line != original_line:
                file_changed = True
                if dry_run:
                    print(f"\n[MATCH] {file_path}:{i+1}")
                    print(f"  - {original_line.strip()}")
                    print(f"  + {current_line.strip()}")
            
            new_lines.append(current_line)

        if file_changed and not dry_run:
            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            print(f"[*] Patched: {file_path}")

    except Exception as e:
        print(f"[!] Error processing {file_path}: {e}")

# ================= SPECIAL LOGIC HANDLERS =================

def patch_server_vala(base_dir, dry_run=False):
    """Randomizes DEFAULT_DIRECTORY in server/server.vala"""
    target = base_dir / "subprojects" / "frida-core" / "server" / "server.vala"
    if not target.exists(): return

    # 1. Change const to static null
    # 2. Inject initialization in main
    
    try:
        with open(target, "r") as f:
            content = f.read()

        orig_content = content
        
        # Replacement 1: Variable Definition
        old_def = 'private const string DEFAULT_DIRECTORY = "re.frida.server";'
        new_def = 'private static string? DEFAULT_DIRECTORY = null;'
        
        if old_def in content:
            content = content.replace(old_def, new_def)
        
        # Replacement 2: Injection in main
        # We look for the main function signature and inject immediately after
        main_sig = 'private static int main (string[] args) {'
        injection = 'private static int main (string[] args) {\n\t\tDEFAULT_DIRECTORY = GLib.Uuid.string_random();'
        
        if main_sig in content and "GLib.Uuid.string_random" not in content:
            content = content.replace(main_sig, injection)

        if content != orig_content:
            if dry_run:
                print(f"\n[MATCH] {target}")
                print("  Applied Server Randomization logic (UUID directory)")
            else:
                with open(target, "w") as f:
                    f.write(content)
                print(f"[*] Patched Server Logic: {target}")
    except Exception as e:
        print(f"[!] Error patching server.vala: {e}")

def patch_linux_host_session(base_dir, dry_run=False):
    """Randomizes agent filenames in src/linux/linux-host-session.vala"""
    target = base_dir / "subprojects" / "frida-core" / "src" / "linux" / "linux-host-session.vala"
    if not target.exists(): return

    try:
        with open(target, "r") as f:
            content = f.read()
            
        orig_content = content

        # We need to replace the AgentDescriptor instantiation to use a random prefix
        # This is a multi-line replacement, so we do it carefully.
        
        # 1. Inject the variable definition before the agent creation
        # We look for the line initiating the AgentDescriptor
        search_str = 'agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),'
        
        replace_str = 'var random_prefix = GLib.Uuid.string_random();\n\t\t\t' + \
                      'agent = new AgentDescriptor (PathTemplate (random_prefix + "-<arch>.so"),'

        if search_str in content:
            content = content.replace(search_str, replace_str)
            
        # 2. Update the resource names to use the variable
        content = content.replace('"frida-agent-arm.so"', 'random_prefix + "-arm.so"')
        content = content.replace('"frida-agent-arm64.so"', 'random_prefix + "-arm64.so"')

        if content != orig_content:
            if dry_run:
                print(f"\n[MATCH] {target}")
                print("  Applied Linux Host Session Randomization (Agent Filenames)")
            else:
                with open(target, "w") as f:
                    f.write(content)
                print(f"[*] Patched Linux Host Session: {target}")
    except Exception as e:
        print(f"[!] Error patching linux-host-session.vala: {e}")


def disable_tests(base_dir, dry_run=False):
    """Comments out subdir('tests') in meson.build files."""
    print(f"\n[*] Scanning to disable tests...")
    replacements = [(r"subdir\('tests'\)", "# subdir('tests')")]
    for sub in TARGET_SUBPROJECTS:
        target_path = base_dir / "subprojects" / sub
        if not target_path.exists(): continue
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if "meson.build" in files:
                process_file(os.path.join(root, "meson.build"), replacements, dry_run)

def inject_embed_agent(base_dir, dry_run=False):
    """Injects Python execution logic into embed-agent.py"""
    embed_script = base_dir / "subprojects" / "frida-core" / "src" / "embed-agent.py"
    if not embed_script.exists(): return

    hook_point = 'shutil.copy(agent, embedded_agent)'
    injection_code = """
                shutil.copy(agent, embedded_agent)
                # --- STEALTH INJECTION START ---
                try:
                    custom_script = output_dir / "../../../../frida-core/src/anti-anti-frida.py"
                    if custom_script.exists():
                        print(f"Running stealth script on {embedded_agent}")
                        subprocess.run([sys.executable, str(custom_script), str(embedded_agent)], check=True)
                except Exception as e:
                    print(f"Warning: Stealth script failed: {e}")
                # --- STEALTH INJECTION END ---
    """
    try:
        with open(embed_script, "r") as f:
            content = f.read()
        if hook_point in content and "STEALTH INJECTION" not in content:
            if dry_run:
                print(f"\n[MATCH] {embed_script}\n  Injecting stealth runner logic.")
            else:
                new_content = content.replace(hook_point, injection_code)
                with open(embed_script, "w") as f:
                    f.write(new_content)
                print(f"[*] Injected code into: {embed_script}")
    except Exception as e:
        print(f"[!] Error handling embed-agent.py: {e}")

def create_anti_frida_script(base_dir, config, dry_run=False):
    """Generates the anti-anti-frida.py script using the provided naming config."""
    aaf_path = base_dir / "subprojects" / "frida-core" / "src" / "anti-anti-frida.py"
    if dry_run:
        print(f"\n[CREATE] Would create file: {aaf_path}")
        return

    new_main_symbol = f"{config['name_lower']}_main"
    content = f"""import lief
import sys
import random
import os

def replacer(input_file):
    print(f"[*] Patching binary: {{input_file}}")
    random_name = "".join(random.sample("ABCDEFGHIJKLMNO", 5))
    
    try:
        binary = lief.parse(input_file)
        if not binary: return

        for symbol in binary.symbols:
            if symbol.name == "frida_agent_main":
                symbol.name = "{new_main_symbol}"
            if "frida" in symbol.name:
                symbol.name = symbol.name.replace("frida", random_name)
            if "FRIDA" in symbol.name:
                symbol.name = symbol.name.replace("FRIDA", random_name)
        
        binary.write(input_file)
    except Exception as e:
        print(f"LIEF Error: {{e}}")

    # Use sed for string replacement in raw binary
    rand_gum = "".join(random.sample("abcdefghijklmn", 11))
    os.system(f"sed -i s/gum-js-loop/{{rand_gum}}/g {{input_file}}")
    
    rand_main = "".join(random.sample("abcdefghijklmn", 5))
    os.system(f"sed -i s/gmain/{{rand_main}}/g {{input_file}}")

if __name__ == "__main__":
    for path in sys.argv[1:]:
        if path and os.path.exists(path):
            replacer(path)
"""
    with open(aaf_path, "w") as f:
        f.write(content)
    print(f"[*] Created: {aaf_path}")

def main():
    parser = argparse.ArgumentParser(description="Frida Stealth Patcher")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX, help=f"Name to replace 'Frida' with (default: {DEFAULT_PREFIX})")
    parser.add_argument("--port-control", default=DEFAULT_PORT_CONTROL, help=f"New Control Port (default: {DEFAULT_PORT_CONTROL})")
    parser.add_argument("--port-cluster", default=DEFAULT_PORT_CLUSTER, help=f"New Cluster Port (default: {DEFAULT_PORT_CLUSTER})")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes with diff-style output")
    args = parser.parse_args()

    config = {
        'name': args.prefix,
        'name_lower': args.prefix.lower(),
        'thread_prefix': f"{args.prefix.lower()}-",
        'bundle_id': f"re.{args.prefix.lower()}",
        'port_control': args.port_control,
        'port_cluster': args.port_cluster
    }

    cwd = pathlib.Path.cwd()
    base_dir = cwd / "frida"
    if not base_dir.exists():
        base_dir = cwd 
    
    print(f"[*] Target: {base_dir}")
    print(f"[*] Config: Name={config['name']}, ControlPort={config['port_control']}")
    print(f"[*] Mode: {'DRY RUN (No changes)' if args.dry_run else 'LIVE PATCHING'}")

    replacements = get_replacements(config)

    # 1. Recursive Scan for generic replacements
    for sub in TARGET_SUBPROJECTS:
        target_path = base_dir / "subprojects" / sub
        if not target_path.exists():
            continue

        print(f"[*] Scanning {sub}...")
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for file in files:
                if file.endswith((".c", ".cc", ".cpp", ".h", ".vala", ".py", ".sh", "meson.build")):
                    process_file(os.path.join(root, file), replacements, args.dry_run)

    # 2. Run Special Logic Handlers
    patch_server_vala(base_dir, args.dry_run)
    patch_linux_host_session(base_dir, args.dry_run)
    
    # 3. Standard Tasks
    disable_tests(base_dir, args.dry_run)
    inject_embed_agent(base_dir, args.dry_run)
    create_anti_frida_script(base_dir, config, args.dry_run)

if __name__ == "__main__":
    main()