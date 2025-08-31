#!/usr/bin/env python3
import os
import sys
import json
import shutil
import hashlib
import tarfile
import zipfile
import subprocess
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple, Dict, List

"""
LFS Manager – Ambientes, receitas e gerenciamento de pacotes para LFS

Funcionalidades principais:

✔ Ambientes: create, chroot (com bind-mounts de /dev, /proc, /sys, /run)
✔ Receitas individuais: /repo/{base,x11,extras,desktop}/<nome-versao>/recipe.json
✔ Dependências: campo "depends" em recipe.json (DFS pós-ordem)
✔ Download: curl (URLs http/https/ftp), git clone para URLs com prefixo "git+"
✔ Checksum: verificação sha256 opcional
✔ Extração: .tar.*, .zip (fallback bsdtar)
✔ Hooks por ciclo de vida: preconfig, prepare, build, preinstall, install, postinstall, postremove
✔ Variáveis nos hooks: LFS_ENV, ROOTFS, PKG_NAME, PKG_VERSION, PKG_DIR, CATEGORY, SOURCES, SRC_DIR, BUILD_DIR, PREFIX, REPO, PKGS, PKGROOT
✔ Binários: pkgbuild (fakeroot + DESTDIR em PKGROOT → gera .tar.xz em $PKGS), pkginstall, pkgrm
✔ Banco local: /var/lib/lfs-manager/<env>/installed.json

Observações:
- Para instalar via binário, o fluxo recomendado é: pkgbuild → pkginstall.
- Nos hooks de install, use DESTDIR="$PKGROOT" para gerar o layout final do pacote; o
  pkginstall extrai em $ROOTFS e registra os arquivos.
"""

# --- Caminhos globais ---
LFS_ROOT = Path("/mnt/lfs-manager")            # raiz dos ambientes (ex.: /mnt/lfs-manager/unstable)
REPO_ROOT = Path("/repo")                      # receitas e metadados por pacote
SOURCES = Path("/sources")                     # tarballs e clones git
BUILD_ROOT = Path("/build")                    # área de build temporária
PKGS_ROOT = Path("/pkgs")                      # raiz para armazenar pacotes binários por ambiente
DB_ROOT = Path("/var/lib/lfs-manager")         # banco de pacotes instalados por ambiente

CATEGORIES = ["base", "x11", "extras", "desktop"]
HOOK_ORDER = ["preconfig", "prepare", "build", "preinstall", "install", "postinstall"]

# --- Utils ---

def sh(cmd: str, cwd: Optional[Path] = None, env: Optional[dict] = None):
    print(f"[+] $ {cmd}")
    subprocess.run(cmd, shell=True, check=True, cwd=str(cwd) if cwd else None, env=env)


def which_or_warn(binary: str):
    if shutil.which(binary) is None:
        print(f"[!] Aviso: '{binary}' não encontrado no PATH")


def ensure_requirements():
    for b in ("curl", "git", "tar"):
        which_or_warn(b)


def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def env_paths(env: str) -> Dict[str, Path]:
    rootfs = LFS_ROOT / env
    return {
        "ROOTFS": rootfs,
        "BIN": rootfs / "bin",
        "SBIN": rootfs / "sbin",
        "USR": rootfs / "usr",
        "VAR": rootfs / "var",
        "ETC": rootfs / "etc",
        "PROC": rootfs / "proc",
        "SYS": rootfs / "sys",
        "DEV": rootfs / "dev",
        "RUN": rootfs / "run",
        "PKGS": PKGS_ROOT / env,
        "DBDIR": DB_ROOT / env,
    }

# --- Receitas ---

def find_recipe(package: str, version: Optional[str] = None) -> Tuple[Path, dict]:
    """Procura /repo/<cat>/<package-version>/recipe.json. Se version=None, pega a de maior nome."""
    candidates: List[Path] = []
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
        raise FileNotFoundError(f"Receita não encontrada para '{package}'{(' ' + version) if version else ''}")
    candidates.sort(key=lambda p: p.name)
    pkg_dir = candidates[-1]
    with (pkg_dir / "recipe.json").open() as f:
        recipe = json.load(f)
    return pkg_dir, recipe

# --- Download / verificação / extração ---

def download_source(url: str, pkg_name: str, version: str) -> Path:
    SOURCES.mkdir(parents=True, exist_ok=True)
    if url.startswith("git+"):
        git_url = url[4:]
        dst = SOURCES / f"{pkg_name}-{version}-git"
        if dst.exists():
            print(f"[i] Git já presente, atualizando: {dst}")
            sh("git pull", cwd=dst)
        else:
            sh(f"git clone --depth 1 {git_url} {dst}")
        return dst

    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        raise ValueError(f"URL inválida: {url}")
    filename = os.path.basename(parsed.path)
    dst = SOURCES / filename
    if not dst.exists():
        sh(f"curl -Lf --retry 3 --continue-at - -o {dst} {url}")
    else:
        print(f"[i] Tarball já existe: {dst}")
    return dst


def verify_checksum(artifact: Path, expected: Optional[str]):
    if not expected:
        print("[i] Sem SHA256 – pulando verificação")
        return
    got = sha256sum(artifact)
    if got != expected:
        raise RuntimeError(f"Checksum inválido: esperado {expected}, obtido {got}")
    print("[✓] Checksum OK")


def extract_source(src: Path, build_dir: Path) -> Path:
    if src.is_dir():
        return src
    build_dir.mkdir(parents=True, exist_ok=True)
    name = src.name
    try:
        if name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tar")):
            with tarfile.open(src, "r:*") as tar:
                tar.extractall(build_dir)
            roots = [p for p in build_dir.iterdir() if p.is_dir()]
            return roots[0] if roots else build_dir
        elif name.endswith(".zip"):
            with zipfile.ZipFile(src, "r") as z:
                z.extractall(build_dir)
            roots = [p for p in build_dir.iterdir() if p.is_dir()]
            return roots[0] if roots else build_dir
        else:
            print("[i] Formato não reconhecido pelo Python – tentando bsdtar")
            sh(f"bsdtar -xf {src}", cwd=build_dir)
            roots = [p for p in build_dir.iterdir() if p.is_dir()]
            return roots[0] if roots else build_dir
    except Exception as e:
        raise RuntimeError(f"Falha ao extrair {src}: {e}")

# --- Dependências ---

def resolve_deps(package: str, version: Optional[str] = None, seen=None, order=None):
    if seen is None:
        seen = set()
    if order is None:
        order = []
    key = f"{package}@{version or '*'}"
    if key in seen:
        return order
    seen.add(key)
    _, recipe = find_recipe(package, version)
    for dep in recipe.get("depends", []) or []:
        dep_name, dep_ver = dep, None
        if "==" in dep:
            dep_name, dep_ver = dep.split("==", 1)
        resolve_deps(dep_name, dep_ver, seen, order)
    order.append((package, version))
    return order

# --- Ambientes ---

def create_env(env: str):
    p = env_paths(env)
    for k, d in p.items():
        if k in ("ROOTFS", "PKGS", "DBDIR") or k.isupper():
            d.mkdir(parents=True, exist_ok=True)
    print(f"[✓] Ambiente criado em {p['ROOTFS']}")


def chroot_env(env: str):
    p = env_paths(env)
    rootfs = p["ROOTFS"]
    if not rootfs.exists():
        raise FileNotFoundError(f"Ambiente não existe: {rootfs}")
    for src, dst in (("/dev", p["DEV"]), ("/proc", p["PROC"]), ("/sys", p["SYS"]), ("/run", p["RUN"])):
        dst.mkdir(parents=True, exist_ok=True)
        try:
            sh(f"mount --bind {src} {dst}")
        except subprocess.CalledProcessError:
            print(f"[i] bind já montado ou sem permissão: {dst}")
    cmd = (
        f"chroot {rootfs} /usr/bin/env -i HOME=/root TERM=\"$TERM\" "
        f"PS1='(lfs-{env}) \\u@\\h:\\w\\$ ' PATH=/bin:/usr/bin:/sbin:/usr/sbin /bin/bash --login"
    )
    sh(cmd)

# --- Build (fonte) ---

def build(env: str, package: str, version: Optional[str] = None):
    ensure_requirements()
    seq = resolve_deps(package, version)
    print("[i] Ordem de build:")
    for n, v in seq:
        print(f"  - {n}{'-' + v if v else ''}")
    for n, v in seq:
        build_one(env, n, v)


def build_one(env: str, package: str, version: Optional[str] = None):
    pkg_dir, recipe = find_recipe(package, version)
    name = recipe.get("name", package)
    version = recipe["version"]
    category = recipe.get("category", "base")
    url = recipe.get("url")
    sha256 = recipe.get("sha256")

    env_build_root = BUILD_ROOT / env / f"{name}-{version}"
    if env_build_root.exists():
        shutil.rmtree(env_build_root)
    env_build_root.mkdir(parents=True, exist_ok=True)

    src = download_source(url, name, version)
    if src.is_file():
        verify_checksum(src, sha256)
    src_dir = extract_source(src, env_build_root)

    p = env_paths(env)
    rootfs = p["ROOTFS"]
    prefix = "/usr"

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
        "PKGS": str(p["PKGS"]),
        "PKGROOT": str(env_build_root / "pkgroot"),
    })

    hooks = recipe.get("hooks", {})
    for step in HOOK_ORDER:
        cmd = hooks.get(step)
        if not cmd:
            continue
        sh(cmd, cwd=Path(env_vars["SRC_DIR"]), env=env_vars)

    # Marca de build (sem binário)
    artifact = pkg_dir / f"{name}-{version}.built"
    artifact.write_text(f"Built {name}-{version} for env {env}\n")
    print(f"[✓] Build fonte finalizado: {artifact}")

# --- Pacotes binários (.tar.xz) ---

def _collect_file_list(base: Path) -> List[str]:
    files: List[str] = []
    for path in sorted(base.rglob('*')):
        rel = path.relative_to(base)
        files.append("/" + str(rel))
    return files


def pkgbuild(env: str, package: str, version: Optional[str] = None, use_fakeroot: bool = True):
    ensure_requirements()
    pkg_dir, recipe = find_recipe(package, version)
    name = recipe.get("name", package)
    version = recipe["version"]
    category = recipe.get("category", "base")
    url = recipe.get("url")
    sha256 = recipe.get("sha256")

    env_build_root = BUILD_ROOT / env / f"{name}-{version}"
    if env_build_root.exists():
        shutil.rmtree(env_build_root)
    env_build_root.mkdir(parents=True, exist_ok=True)
    pkgroot = env_build_root / "pkgroot"
    pkgroot.mkdir(parents=True, exist_ok=True)

    src = download_source(url, name, version)
    if src.is_file():
        verify_checksum(src, sha256)
    src_dir = extract_source(src, env_build_root)

    p = env_paths(env)
    p["PKGS"].mkdir(parents=True, exist_ok=True)
    prefix = "/usr"

    env_vars = os.environ.copy()
    env_vars.update({
        "LFS_ENV": env,
        "ROOTFS": str(p["ROOTFS"]),
        "PKG_NAME": name,
        "PKG_VERSION": version,
        "PKG_DIR": str(pkg_dir),
        "CATEGORY": category,
        "SOURCES": str(SOURCES),
        "SRC_DIR": str(src_dir),
        "BUILD_DIR": str(env_build_root),
        "PREFIX": prefix,
        "REPO": str(REPO_ROOT),
        "PKGS": str(p["PKGS"]),
        "PKGROOT": str(pkgroot),
    })

    hooks = recipe.get("hooks", {})
    # Executa até preinstall normal
    for step in ["preconfig", "prepare", "build", "preinstall"]:
        cmd = hooks.get(step)
        if not cmd:
            continue
        sh(cmd, cwd=src_dir, env=env_vars)

    # Install sob fakeroot + DESTDIR=$PKGROOT
    install_cmd = hooks.get("install")
    if install_cmd:
        install_full = f"DESTDIR=\"{pkgroot}\" {install_cmd}"
        if use_fakeroot:
            install_full = f"fakeroot /bin/sh -c \"{install_full}\""
        sh(install_full, cwd=src_dir, env=env_vars)

    # Postinstall (ainda no host; evite comandos que precisem do chroot)
    if hooks.get("postinstall"):
        sh(hooks["postinstall"], cwd=src_dir, env=env_vars)

    # Gera manifest do pacote binário
    file_list = _collect_file_list(pkgroot)
    pkg_manifest = {
        "name": name,
        "version": version,
        "category": category,
        "files": file_list,
    }
    (env_build_root / "manifest.json").write_text(json.dumps(pkg_manifest, indent=2))

    # Cria tar.xz
    out_tar = p["PKGS"] / f"{name}-{version}.tar.xz"
    with tarfile.open(out_tar, mode="w:xz") as tf:
        # Conteúdo do pacote (a partir de pkgroot)
        tf.add(pkgroot, arcname=".")
        # Manifesto interno (em .PKGINFO.json)
        info_bytes = json.dumps(pkg_manifest, indent=2).encode()
        info = tarfile.TarInfo(name=".PKGINFO.json")
        info.size = len(info_bytes)
        tf.addfile(info, io.BytesIO(info_bytes))

    print(f"[✓] Pacote binário gerado: {out_tar}")
    return out_tar

# helper para BytesIO
import io

# --- Banco de pacotes instalados ---

def _db_load(env: str) -> dict:
    d = env_paths(env)["DBDIR"]
    d.mkdir(parents=True, exist_ok=True)
    dbf = d / "installed.json"
    if not dbf.exists():
        return {}
    return json.loads(dbf.read_text())


def _db_save(env: str, data: dict):
    d = env_paths(env)["DBDIR"]
    d.mkdir(parents=True, exist_ok=True)
    dbf = d / "installed.json"
    dbf.write_text(json.dumps(data, indent=2))

# --- Instalar/remover binários ---

def pkginstall(env: str, pkg_spec: str):
    """pkg_spec pode ser caminho para .tar.xz ou nome-versão (procura em $PKGS)."""
    p = env_paths(env)
    rootfs = p["ROOTFS"]
    pkgs_dir = p["PKGS"]

    tar_path = Path(pkg_spec)
    if not tar_path.exists():
        # procurar por nome-versão
        tar_path = pkgs_dir / f"{pkg_spec}.tar.xz"
        if not tar_path.exists():
            raise FileNotFoundError(f"Pacote não encontrado: {pkg_spec}")

    print(f"[+] Instalando {tar_path} em {rootfs}")
    with tarfile.open(tar_path, "r:xz") as tf:
        tf.extractall(rootfs)
        # tenta ler manifesto interno
        try:
            member = tf.getmember(".PKGINFO.json")
            bio = tf.extractfile(member)
            meta = json.loads(bio.read().decode()) if bio else {}
        except KeyError:
            meta = {"name": tar_path.stem.split("-")[0], "version": "unknown", "files": []}

    # Se o manifesto não listou arquivos, gera a partir do tar
    if not meta.get("files"):
        # Optionally: reabrir para listar; aqui vamos fazer um scan rápido do rootfs pela data de extração…
        # Simples: não listar, deixar vazio.
        pass

    db = _db_load(env)
    key = f"{meta.get('name')}-{meta.get('version')}"
    db[key] = {"files": meta.get("files", []), "category": meta.get("category")}
    _db_save(env, db)
    print(f"[✓] Instalado: {key}")

    # Rodar postinstall do recipe (se existir)
    try:
        pkg_dir, recipe = find_recipe(meta.get("name"), meta.get("version"))
        hooks = recipe.get("hooks", {})
        if hooks.get("postinstall"):
            env_vars = os.environ.copy()
            env_vars.update({
                "LFS_ENV": env,
                "ROOTFS": str(rootfs),
                "PKG_NAME": meta.get("name"),
                "PKG_VERSION": meta.get("version"),
                "PKG_DIR": str(pkg_dir),
                "REPO": str(REPO_ROOT),
                "PKGS": str(pkgs_dir),
            })
            sh(hooks["postinstall"], cwd=pkg_dir, env=env_vars)
    except FileNotFoundError:
        pass


def pkgrm(env: str, pkg_with_ver: str):
    p = env_paths(env)
    rootfs = p["ROOTFS"]
    db = _db_load(env)
    if pkg_with_ver not in db:
        print(f"[!] {pkg_with_ver} não consta como instalado no banco; tentativa de remoção forçada")
        installed_files: List[str] = []
    else:
        installed_files = db[pkg_with_ver].get("files", [])

    # Remove arquivos
    removed = 0
    for f in installed_files:
        path = rootfs / f.lstrip('/')
        try:
            if path.is_dir() and not path.is_symlink():
                # não removemos diretórios recursivamente; muitos são compartilhados
                continue
            path.unlink()
            removed += 1
        except FileNotFoundError:
            continue
        except IsADirectoryError:
            # ignorar diretórios
            continue

    print(f"[i] Arquivos removidos: {removed}")

    # Hook postremove
    try:
        name, ver = pkg_with_ver.split('-', 1)
        pkg_dir, recipe = find_recipe(name, ver)
        postremove = recipe.get("hooks", {}).get("postremove")
        if postremove:
            env_vars = os.environ.copy()
            env_vars.update({
                "LFS_ENV": env,
                "ROOTFS": str(rootfs),
                "PKG_NAME": name,
                "PKG_VERSION": ver,
                "PKG_DIR": str(pkg_dir),
                "REPO": str(REPO_ROOT),
            })
            sh(postremove, cwd=pkg_dir, env=env_vars)
    except Exception:
        pass

    # Atualiza DB
    if pkg_with_ver in db:
        del db[pkg_with_ver]
        _db_save(env, db)
        print(f"[✓] Removido do banco: {pkg_with_ver}")

# --- Listagem ---

def list_recipes():
    print(f"Receitas em {REPO_ROOT}:")
    for cat in CATEGORIES:
        cat_dir = REPO_ROOT / cat
        if not cat_dir.exists():
            continue
        for d in sorted([p for p in cat_dir.iterdir() if p.is_dir()], key=lambda p: p.name):
            print(f" - {cat}/{d.name}{'' if (d/'recipe.json').exists() else ' (sem recipe.json)'}")


def list_installed(env: str):
    db = _db_load(env)
    if not db:
        print("[i] Nenhum pacote instalado registrado")
        return
    for k, v in db.items():
        print(f" - {k} ({v.get('category','?')}) {len(v.get('files', []))} arquivos")

# --- CLI ---

def usage():
    print(
        """
Uso:
  lfs-manager create <env>
  lfs-manager chroot <env>
  lfs-manager list                 # lista receitas
  lfs-manager list-installed <env>

  lfs-manager build     <env> <package>[==version]
  lfs-manager pkgbuild  <env> <package>[==version]
  lfs-manager pkginstall <env> <nome-versao | caminho.tar.xz>
  lfs-manager pkgrm     <env> <nome-versao>

Exemplos:
  lfs-manager create unstable
  lfs-manager build unstable gcc==13.2.0
  lfs-manager pkgbuild unstable gcc
  lfs-manager pkginstall unstable gcc-13.2.0
  lfs-manager pkgrm unstable gcc-13.2.0
  lfs-manager list
  lfs-manager list-installed unstable
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
        elif cmd == "list":
            list_recipes()
        elif cmd == "list-installed":
            if len(sys.argv) < 3:
                return usage()
            list_installed(sys.argv[2])
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
        elif cmd == "pkgbuild":
            if len(sys.argv) < 4:
                return usage()
            env = sys.argv[2]
            target = sys.argv[3]
            if "==" in target:
                name, ver = target.split("==", 1)
            else:
                name, ver = target, None
            pkgbuild(env, name, ver)
        elif cmd == "pkginstall":
            if len(sys.argv) < 4:
                return usage()
            pkginstall(sys.argv[2], sys.argv[3])
        elif cmd == "pkgrm":
            if len(sys.argv) < 4:
                return usage()
            pkgrm(sys.argv[2], sys.argv[3])
        else:
            usage()
    except Exception as e:
        print(f"[x] Erro: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
