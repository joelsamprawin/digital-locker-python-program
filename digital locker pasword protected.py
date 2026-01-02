import hashlib
import os

LOCK_FILE = "locker.txt"
PASS_FILE = "password.txt"


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def set_password():
    if os.path.exists(PASS_FILE):
        print("Password already set.")
        return

    password = input("Set new locker password: ")
    hashed = hash_password(password)

    with open(PASS_FILE, "w") as f:
        f.write(hashed)

    print("🔐 Password set successfully!")


def lock_file():
    if not os.path.exists(PASS_FILE):
        print("Set password first.")
        return

    content = input("Enter text to lock inside the file:\n")

    with open(LOCK_FILE, "w") as f:
        f.write(content)

    print("📁 File locked successfully!")


def unlock_file():
    if not os.path.exists(LOCK_FILE):
        print("No locked file found.")
        return

    password = input("Enter password to unlock: ")
    hashed = hash_password(password)

    with open(PASS_FILE, "r") as f:
        saved_hash = f.read()

    if hashed == saved_hash:
        print("\n✅ Access Granted. File Content:\n")
        with open(LOCK_FILE, "r") as f:
            print(f.read())
    else:
        print("❌ Wrong password! Access denied.")


def menu():
    print("\n==== Digital Locker ====")
    print("1. Set Password")
    print("2. Lock File")
    print("3. Unlock File")
    print("4. Exit")


while True:
    menu()
    choice = input("Choose option: ")

    if choice == "1":
        set_password()
    elif choice == "2":
        lock_file()
    elif choice == "3":
        unlock_file()
    elif choice == "4":
        print("Exiting locker...")
        break
    else:
        print("Invalid choice.")
