import os
import subprocess
import sys
import shutil
from pathlib import Path

# Diretórios base
LFS_ROOT = Path("/mnt/lfs-manager")
REPO_ROOT = Path("/repo")

# --------------------
# Helpers
# --------------------
def run(cmd):
    print(f"[+] Executando: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

# --------------------
# Comandos
# --------------------
def create(env, toolchain):
    env_dir = LFS_ROOT / env
    (env_dir / "bin").mkdir(parents=True, exist_ok=True)
    print(f"[+] Criado ambiente {env} em {env_dir}")
    print(f"[!] Toolchain alvo: {toolchain} (simulação)")


def build(env, package):
    pkg_dir = REPO_ROOT / env
    pkg_dir.mkdir(parents=True, exist_ok=True)
    artifact = pkg_dir / f"{package}-dummy.pkg"
    with open(artifact, "w") as f:
        f.write(f"Pacote {package} buildado no ambiente {env}\n")
    print(f"[+] Build do {package} concluído → {artifact}")


def chroot_env(env):
    env_dir = LFS_ROOT / env
    if not env_dir.exists():
        print(f"[x] Ambiente {env} não existe!")
        return
    print(f"[+] Entrando no chroot do {env}...")
    run(f"chroot {env_dir} /bin/bash")


def promote(env):
    unstable_repo = REPO_ROOT / env
    stable_repo = REPO_ROOT / "stable"
    if not unstable_repo.exists():
        print(f"[x] Repo {env} não existe!")
        return
    stable_repo.mkdir(parents=True, exist_ok=True)
    # copia pacotes
    for pkg in unstable_repo.glob("*.pkg"):
        shutil.copy(pkg, stable_repo)
        print(f"[+] Promovido {pkg.name} para stable")

# --------------------
# CLI
# --------------------
def main():
    if len(sys.argv) < 2:
        print("Uso: lfs-manager <comando> [args]")
        return

    cmd = sys.argv[1]
    if cmd == "create":
        if len(sys.argv) < 4:
            print("Uso: lfs-manager create <env> <toolchain>")
            return
        create(sys.argv[2], sys.argv[3])

    elif cmd == "build":
        if len(sys.argv) < 4:
            print("Uso: lfs-manager build <env> <package>")
            return
        build(sys.argv[2], sys.argv[3])

    elif cmd == "chroot":
        if len(sys.argv) < 3:
            print("Uso: lfs-manager chroot <env>")
            return
        chroot_env(sys.argv[2])

    elif cmd == "promote":
        if len(sys.argv) < 3:
            print("Uso: lfs-manager promote <env>")
            return
        promote(sys.argv[2])

    else:
        print(f"Comando desconhecido: {cmd}")

if __name__ == "__main__":
    main()
