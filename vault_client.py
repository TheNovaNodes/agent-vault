import sys
import json
import urllib.request
import urllib.error
import os

def get_secret_from_vault(token):
    url = f"http://127.0.0.1:8301/access"
    try:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return data
    except urllib.error.URLError as e:
        print(f"❌ Ошибка подключения к Lab-Vault: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python vault_client.py <token>")
        sys.exit(1)
        
    token = sys.argv[1]
    secrets = get_secret_from_vault(token)
    
    if secrets:
        # Create RAM disk directory if not exists
        os.makedirs("/dev/shm/agent_vault", exist_ok=True)
        os.chmod("/dev/shm/agent_vault", 0o700)
        
        # Save secret securely to RAM disk
        pointer_id = token[-6:]
        secret_path = f"/dev/shm/agent_vault/{pointer_id}"
        
        with open(secret_path, "w") as f:
            f.write(secrets.get('value', ''))
        os.chmod(secret_path, 0o600)
        
        # Fallback cleanup: remove the file after 5 minutes if not consumed
        import subprocess
        subprocess.Popen(['python3', '-c', f'import time, os; time.sleep(300); os.unlink("{secret_path}") if os.path.exists("{secret_path}") else None'])
        
        print("✅ MCP Vault Gateway: Секрет успешно загружен в защищенную память.")
        print("\n--- Открытые метаданные для LLM ---")
        if 'name' in secrets:
            print(f"🏷️ Имя секрета: {secrets['name']}")
        print(f"🔗 Указатель для вызова команд: {pointer_id}")
        print("----------------------------------")
        print(f"💡 Пример: with-secret {pointer_id} --secret-path-env MY_VAR -- cat $MY_VAR")
    else:
        print("❌ Не удалось получить секрет.")
