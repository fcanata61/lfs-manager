#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil
import json
import hashlib
import urllib.parse
import tarfile
import zipfile
from pathlib import Path

"""
LFS Manager – ambientes, receitas e builds para LFS (stable/unstable)

✔ Ambientes: create, chroot
✔ Receitas individuais: /repo/{base,x11,extras,desktop}/<nome-versao>/recipe.json
✔ Download: curl (tarballs), git clone (url começando com git+)
✔ Checksum: sha256 (quando definido)
✔ Extração: .tar.*, .zip (fallback para bsdtar)
✔ Hooks: preconfig, prepare, build, preinstall, install, postinstall, postremove
✔ Variáveis disponíveis nos hooks: LFS_ENV, ROOTFS, PKG_NAME, PKG_VERSION, PKG_DIR, CATEGORY, SOURCES, SRC_DIR, BUILD_DIR, PREFIX, REPO
✔ Dependências: campo "depends" (DFS, com deduplicação)

Observação importante sobre instalação:
- Exponho ROOTFS (raiz do ambiente) e PREFIX (padrão /usr dentro do chroot) para os hooks.
- Recomendo usar DESTDIR="$ROOTFS" nas receitas de install, quando aplicável.
"""

# Diretórios base
LFS_ROOT = Path("/mnt/lfs-manager")          # raiz dos ambientes (ex.: /mnt/lfs-manager/unstable)
REPO_ROOT = Path("/repo")                    # árvore de receitas/pacotes (seu repositório de receitas E artefatos)
SOURCES = Path("/sources")                   # onde tarballs/clones git ficam salvos
BUILD_ROOT = Path("/build")                  # diretórios temporários de build por ambiente/pacote

CATEGORIES = ["base", "x11", "extras", "desktop"]
HOOK_ORDER = ["preconfig", "prepare", "build", "preinstall", "install", "postinstall"]

# --------------------
# Utilitários
# --------------------

def sh(cmd: str, cwd: Path | None = None, env: dict | None = None):
    print(f"[+] $ {cmd}")
    subprocess.run(cmd, shell=True, check=True, cwd=str(cwd) if cwd else None, env=env)


def ensure_requirements():
    # Checagem leve de dependências externas
    for bin in ("curl", "git"):
        if shutil.which(bin) is None:
            print(f"[!] Aviso: '{bin}' não encontrado no PATH. Algumas funcionalidades podem falhar.")


def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def guess_pkg_dirname_from_archive(archive: Path) -> str | None:
    # Tentativa heurística – muitos tarballs extraem para <nome-versao>/
    stem = archive.name
    for ext in (".tar.xz", ".tar.gz", ".tgz", ".tar.bz2", ".tar.zst", ".zip"):
        if stem.endswith(ext):
            return stem[:-len(ext)]
    return None

# --------------------
# Localização de receitas
# --------------------

def find_recipe(package: str, version: str | None = None) -> tuple[Path, dict]:
    """Procura por /repo/<cat>/<name-version>/recipe.json.
    Se version for None, escolhe a "maior" por ordenação natural simples.
    Retorna (dir_do_pacote, recipe_dict).
    """
    candidates: list[Path] = []
    for cat in CATEGORIES:
        cat_dir = REPO_ROOT / cat
        if not cat_dir.exists():
            continue
        for d in cat_dir.iterdir():
            if not d.is_dir():
                continue
            if not d.name.startswith(f"{package}-"):
                continue
            if version and d.name != f"{package}-{version}":
                continue
            if (d / "recipe.json").exists():
                candidates.append(d)

    if not candidates:
        raise FileNotFoundError(f"Receita não encontrada para '{package}'{(' ' + version) if version else ''} em {REPO_ROOT}")

    # Escolhe a "maior" por nome se houver múltiplas
    candidates.sort(key=lambda p: p.name)
    pkg_dir = candidates[-1]

    with (pkg_dir / "recipe.json").open() as f:
        recipe = json.load(f)
    return pkg_dir, recipe


# --------------------
# Download & extração
# --------------------

def download_source(url: str, pkg_name: str, version: str) -> Path:
    """Baixa com curl (http/https/ftp) ou clona com git (prefixo git+). Retorna caminho salvo em /sources."""
    SOURCES.mkdir(parents=True, exist_ok=True)

    if url.startswith("git+"):
        git_url = url[4:]
        dst = SOURCES / f"{pkg_name}-{version}-git"
        if dst.exists():
            print(f"[i] Repositório git já existe: {dst} (pull)")
            sh("git pull", cwd=dst)
        else:
            sh(f"git clone --depth 1 {git_url} {dst}")
        return dst

    # Tarball/arquivo
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        raise ValueError(f"URL inválida: {url}")

    filename = os.path.basename(parsed.path)
    dst = SOURCES / filename

    if not dst.exists():
        # -L segue redirects; -f falha em códigos HTTP >= 400
        sh(f"curl -Lf --retry 3 --continue-at - -o {dst} {url}")
    else:
        print(f"[i] Já existe: {dst}")
    return dst


def verify_checksum(artifact: Path, expected: str | None):
    if not expected:
        print("[i] SHA256 não definido – pulando verificação")
        return
    got = sha256sum(artifact)
    if got != expected:
        raise RuntimeError(f"Checksum inválido: esperado {expected}, obtido {got}")
    print("[✓] Checksum válido")


def extract_source(src: Path, build_dir: Path) -> Path:
    """Extrai src para build_dir. Retorna SRC_DIR (raiz extraída ou diretório git)."""
    if src.is_dir():
        # É um clone git
        return src

    build_dir.mkdir(parents=True, exist_ok=True)

    # Tenta identificar automaticamente o tipo de arquivo
    name = src.name
    try:
        if name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tar")):
            mode = "r:*"  # tarfile detecta compressão
            with tarfile.open(src, mode) as tar:
                tar.extractall(build_dir)
            top = guess_pkg_dirname_from_archive(src)
            if top and (build_dir / top).exists():
                return build_dir / top
            # fallback: pega primeiro nível
            roots = [p for p in build_dir.iterdir() if p.is_dir()]
            return roots[0] if roots else build_dir
        elif name.endswith(".zip"):
            with zipfile.ZipFile(src, "r") as z:
                z.extractall(build_dir)
            tops = [p for p in build_dir.iterdir() if p.is_dir()]
            return tops[0] if tops else build_dir
        else:
            # Fallback genérico via bsdtar
            print("[i] Formato não reconhecido pelo Python – tentando bsdtar")
            sh(f"bsdtar -xf {src}", cwd=build_dir)
            tops = [p for p in build_dir.iterdir() if p.is_dir()]
            return tops[0] if tops else build_dir
    except Exception as e:
        raise RuntimeError(f"Falha ao extrair {src}: {e}")


# --------------------
# Ambientes
# --------------------

def env_paths(env: str) -> dict:
    rootfs = LFS_ROOT / env
    return {
        "ROOTFS": rootfs,
        "BIN": rootfs / "bin",
        "SBIN": rootfs / "sbin",
        "USR": rootfs / "usr",
        "VAR": rootfs / "var",
        "ETC": rootfs / "etc",
    }


def create_env(env: str):
    paths = env_paths(env)
    rootfs: Path = paths["ROOTFS"]
    for d in (paths["BIN"], paths["SBIN"], paths["USR"], paths["VAR"], paths["ETC"], rootfs / "proc", rootfs / "sys", rootfs / "dev", rootfs / "run"):
        d.mkdir(parents=True, exist_ok=True)
    print(f"[+] Ambiente criado em {rootfs}")
    print("[i] Dica: monte binds e entre no chroot com 'lfs-manager chroot <env>'")


def chroot_env(env: str):
    p = env_paths(env)
    rootfs = p["ROOTFS"]
    if not rootfs.exists():
        raise FileNotFoundError(f"Ambiente '{env}' não existe em {rootfs}")

    # Monta binds básicos (idempotente)
    for src, dst in (("/dev", rootfs / "dev"), ("/proc", rootfs / "proc"), ("/sys", rootfs / "sys"), ("/run", rootfs / "run")):
        dst.mkdir(parents=True, exist_ok=True)
        try:
            sh(f"mount --bind {src} {dst}")
        except subprocess.CalledProcessError:
            print(f"[i] Já montado ou sem permissão: {dst}")

    # Entra no chroot
    cmd = (
        f"chroot {rootfs} /usr/bin/env -i HOME=/root TERM=\"$TERM\" "
        f"PS1='(lfs-{env}) \\u@\\h:\\w\\$ ' PATH=/bin:/usr/bin:/sbin:/usr/sbin /bin/bash --login"
    )
    sh(cmd)


# --------------------
# Build com dependências
# --------------------

def resolve_deps(package: str, version: str | None, seen: set[str] | None = None, order: list[tuple[str,str|None]] | None = None):
    """Preenche 'order' com (pkg, ver) em DFS pós-ordem."""
    if seen is None:
        seen = set()
    if order is None:
        order = []

    key = f"{package}@{version or '*'}"
    if key in seen:
        return order
    seen.add(key)

    pkg_dir, recipe = find_recipe(package, version)
    deps = recipe.get("depends", []) or []
    for dep in deps:
        # dep pode ser "nome" ou "nome==versao" (opcional)
        dep_name = dep
        dep_ver = None
        if "==" in dep:
            dep_name, dep_ver = dep.split("==", 1)
        resolve_deps(dep_name, dep_ver, seen, order)

    order.append((package, version))
    return order


def build(env: str, package: str, version: str | None = None):
    ensure_requirements()

    build_sequence = resolve_deps(package, version)
    print("[i] Ordem de build:")
    for n, v in build_sequence:
        print(f"  - {n}{'-' + v if v else ''}")

    for pkg, ver in build_sequence:
        build_one(env, pkg, ver)


def build_one(env: str, package: str, version: str | None = None):
    pkg_dir, recipe = find_recipe(package, version)
    category = recipe.get("category", "base")
    name = recipe.get("name", package)
    version = recipe.get("version")
    url = recipe.get("url")
    sha256 = recipe.get("sha256")

    # Paths específicos de build
    env_build_root = BUILD_ROOT / env / f"{name}-{version}"
    if env_build_root.exists():
        shutil.rmtree(env_build_root)
    env_build_root.mkdir(parents=True, exist_ok=True)

    # Download & verificação
    src = download_source(url, name, version)
    if src.is_file():
        verify_checksum(src, sha256)

    # Extração
    src_dir = extract_source(src, env_build_root)

    # Ambiente para hooks
    paths = env_paths(env)
    rootfs = paths["ROOTFS"]
    prefix = "/usr"  # prefixo lógico dentro do chroot

    env_vars = os.environ.copy()
    env_vars.update({
        "LFS_ENV": env,
        "ROOTFS": str(rootfs),
        "PKG_NAME": name,
        "PKG_VERSION": version,
        "PKG_DIR": str(pkg_dir),
        "CATEGORY": category,
        "SOURCES": str(SOURCES),
        "SRC_DIR": str(src_dir),
        "BUILD_DIR": str(env_build_root),
        "PREFIX": prefix,
        "REPO": str(REPO_ROOT),
    })

    # Executa hooks
    hooks = recipe.get("hooks", {})
    for step in HOOK_ORDER:
        cmd = hooks.get(step)
        if not cmd:
            continue
        # Se a receita usar DESTDIR, use DESTDIR=$ROOTFS; se não, a própria receita deve lidar com DESTDIR.
        # Não forçamos DESTDIR aqui para não quebrar receitas customizadas.
        sh(cmd, cwd=Path(env_vars["SRC_DIR"]), env=env_vars)

    # Gera um artefato simples (marca de build) dentro do repositório da receita
    artifact = pkg_dir / f"{name}-{version}.pkg"
    with artifact.open("w") as f:
        f.write(f"Built {name}-{version} for env {env}\n")
    print(f"[✓] Build concluído: {artifact}")


# --------------------
# Remoção (hook pós-remover)
# --------------------

def remove(env: str, package_with_ver: str):
    # Aceita "nome" (usa receita mais recente) ou "nome-versao"
    if "-" in package_with_ver:
        pkg, ver = package_with_ver.split("-", 1)
    else:
        pkg, ver = package_with_ver, None

    pkg_dir, recipe = find_recipe(pkg, ver)
    name = recipe.get("name", pkg)
    version = recipe.get("version")

    paths = env_paths(env)
    env_vars = os.environ.copy()
    env_vars.update({
        "LFS_ENV": env,
        "ROOTFS": str(paths["ROOTFS"]),
        "PKG_NAME": name,
        "PKG_VERSION": version,
        "PKG_DIR": str(pkg_dir),
        "REPO": str(REPO_ROOT),
    })

    postremove = recipe.get("hooks", {}).get("postremove")
    if postremove:
        sh(postremove, cwd=Path(pkg_dir), env=env_vars)

    # Remove artefato .pkg se existir
    art = pkg_dir / f"{name}-{version}.pkg"
    if art.exists():
        art.unlink()
        print(f"[i] Artefato removido: {art}")

    print(f"[✓] Remoção lógica de {name}-{version} concluída (ajustes reais dependem do hook postremove)")


# --------------------
# Listagem
# --------------------

def list_packages():
    print(f"Receitas em {REPO_ROOT}:")
    for cat in CATEGORIES:
        cat_dir = REPO_ROOT / cat
        if not cat_dir.exists():
            continue
        for d in sorted([p for p in cat_dir.iterdir() if p.is_dir()], key=lambda p: p.name):
            tag = d.name
            has = (d / "recipe.json").exists()
            print(f" - {cat}/{tag}{'' if has else ' (sem recipe.json)'}")


# --------------------
# CLI
# --------------------

def usage():
    print(
        """
Uso:
  lfs-manager create <env>
  lfs-manager chroot <env>
  lfs-manager build  <env> <package>[==version]
  lfs-manager remove <env> <package>[-version]
  lfs-manager list

Exemplos:
  lfs-manager create unstable
  lfs-manager build  unstable gcc==13.2.0
  lfs-manager build  unstable glibc            # pega a versão mais alta
  lfs-manager remove unstable gcc-13.2.0
  lfs-manager chroot unstable
  lfs-manager list
"""
    )


def main():
    if len(sys.argv) < 2:
        usage()
        return

    cmd = sys.argv[1]
    try:
        if cmd == "create":
            if len(sys.argv) < 3:
                return usage()
            create_env(sys.argv[2])

        elif cmd == "chroot":
            if len(sys.argv) < 3:
                return usage()
            chroot_env(sys.argv[2])

        elif cmd == "build":
            if len(sys.argv) < 4:
                return usage()
            env = sys.argv[2]
            target = sys.argv[3]
            if "==" in target:
                name, ver = target.split("==", 1)
            else:
                name, ver = target, None
            build(env, name, ver)

        elif cmd == "remove":
            if len(sys.argv) < 4:
                return usage()
            remove(sys.argv[2], sys.argv[3])

        elif cmd == "list":
            list_packages()

        else:
            usage()
    except Exception as e:
        print(f"[x] Erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
