import os
import time
import subprocess
import hashlib

# 要监控的目录
WATCHED_DIR = "./"
CHECK_INTERVAL = 5  # 每5秒检测一次

def hash_directory(path):
    sha = hashlib.sha256()
    for root, dirs, files in os.walk(path):
        for fname in sorted(files):
            if fname.startswith(".") or fname == __file__:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as f:
                    while chunk := f.read(8192):
                        sha.update(chunk)
            except:
                continue
    return sha.hexdigest()

def git_push():
    subprocess.call(["git", "add", "."])
    subprocess.call(["git", "commit", "-m", "auto update"])
    subprocess.call(["git", "push", "origin", "main"])

def main():
    print("开始监测代码变更...")
    last_hash = hash_directory(WATCHED_DIR)
    while True:
        time.sleep(CHECK_INTERVAL)
        new_hash = hash_directory(WATCHED_DIR)
        if new_hash != last_hash:
            print("检测到更新，开始推送...")
            git_push()
            last_hash = new_hash
        else:
            print("无变化")

if __name__ == "__main__":
    main()
