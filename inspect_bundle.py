import zipfile
import os

BUNDLE_PATH = "../pcap2/host_192.168.1.46_bundle.zip"


def inspect_zip():
    print(f"[*] Inspecting: {BUNDLE_PATH}")
    try:
        if not os.path.exists(BUNDLE_PATH):
            print("[!] File not found.")
            return

        with zipfile.ZipFile(BUNDLE_PATH, "r") as zf:
            file_list = zf.namelist()
            print(f"[+] Found {len(file_list)} files inside.\n")

            for name in file_list:
                info = zf.getinfo(name)
                print(f" - {name} ({info.file_size} bytes)")

                # If it's a text/csv/log file, read a bit of it
                if name.endswith((".txt", ".csv", ".log", ".md", ".json", ".xml")):
                    print(f"   [Reading Content of {name}]")
                    try:
                        with zf.open(name) as f:
                            content = f.read(500).decode(
                                errors="ignore"
                            )  # Read first 500 bytes
                            print(f"   ---\n{content}\n   ---\n")
                    except Exception as e:
                        print(f"   [!] Could not read: {e}")

    except Exception as e:
        print(f"[!] Error: {e}")


if __name__ == "__main__":
    inspect_zip()
