"""
Ejecucion de comandos y generacion de llaves.

Regla del modulo: nunca `shell=True` y nunca un secreto en la linea de
comandos. Los argumentos van como lista y las llaves privadas viajan por
stdin, porque `/proc/<pid>/cmdline` es legible por cualquier usuario de la
maquina mientras el proceso vive.
"""

import os
import subprocess
import tempfile

import config


class WgError(Exception):
    """Un comando externo fallo."""


def run(args: list[str], stdin: str | None = None, check: bool = True) -> str:
    """Ejecuta un comando sin shell y devuelve su stdout ya limpio."""
    try:
        result = subprocess.run(
            args,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise WgError(f"No se encontro el ejecutable '{args[0]}'. ¿Esta instalado?")
    except subprocess.TimeoutExpired:
        raise WgError(f"'{' '.join(args)}' excedio el tiempo de espera.")

    if check and result.returncode != 0:
        detalle = (result.stderr or result.stdout).strip() or "sin detalle"
        raise WgError(f"'{' '.join(args)}' fallo (codigo {result.returncode}): {detalle}")

    return result.stdout.strip()


def generate_keys() -> tuple[str, str, str]:
    """Devuelve (privada, publica, preshared). La privada nunca pasa por argv."""
    priv = run(["wg", "genkey"])
    pub = run(["wg", "pubkey"], stdin=priv)
    psk = run(["wg", "genpsk"])
    if not (priv and pub and psk):
        raise WgError("La generacion de llaves devolvio un valor vacio.")
    return priv, pub, psk


def get_server_pubkey(interface: str | None = None) -> str:
    interface = interface or config.WG_INTERFACE
    pub = run(["wg", "show", interface, "public-key"])
    if not pub:
        raise WgError(
            f"La interfaz '{interface}' no devolvio llave publica. "
            f"¿Esta levantada? (systemctl status wg-quick@{interface})"
        )
    return pub


def sync_wireguard_hot(interface: str | None = None) -> None:
    """
    Aplica el .conf a la interfaz viva sin cortar los tuneles existentes.

    Lanza WgError si algo falla. La version anterior devolvia siempre True
    porque comparaba contra None un valor que nunca era None: una sincronizacion
    fallida se reportaba como exitosa.
    """
    interface = interface or config.WG_INTERFACE
    stripped = run(["wg-quick", "strip", interface])
    if not stripped:
        raise WgError(f"'wg-quick strip {interface}' no devolvio configuracion.")

    tmp_path = None
    try:
        # mkstemp crea con permisos 600: el fichero contiene la llave privada
        # del servidor durante el instante que dura la sincronizacion.
        fd, tmp_path = tempfile.mkstemp(prefix="wg-sync-", suffix=".conf")
        with os.fdopen(fd, "w") as fh:
            fh.write(stripped)
        run(["wg", "syncconf", interface, tmp_path])
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.remove(tmp_path)
