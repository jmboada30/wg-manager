"""
Configuracion de wg-manager.

Toda la parametrizacion vive aqui y sale de un fichero .env. El modulo se
valida a si mismo al importarse: si algo falta o es incoherente, el programa
falla al arrancar con un mensaje claro en vez de escribir una configuracion
de WireGuard rota.

Orden de busqueda del .env:
  1. Ruta en la variable de entorno WG_MANAGER_ENV
  2. /etc/wg-manager/.env
  3. .env junto a este fichero
Las variables ya presentes en el entorno tienen prioridad sobre el .env.
"""

import ipaddress
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ConfigError(Exception):
    """Configuracion ausente o incoherente."""


def _load_env_file() -> str | None:
    """Carga el primer .env que exista. Devuelve la ruta usada, o None."""
    candidates = [
        os.environ.get("WG_MANAGER_ENV"),
        "/etc/wg-manager/.env",
        os.path.join(BASE_DIR, ".env"),
    ]
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                # El entorno real gana: permite sobreescribir sin editar el .env
                os.environ.setdefault(key, value)
        return path
    return None


ENV_FILE = _load_env_file()


def _get(key: str, default: str | None = None, required: bool = False) -> str:
    value = os.environ.get(key, default)
    if required and not value:
        raise ConfigError(
            f"Falta la variable obligatoria '{key}'. "
            f"Definela en el .env (ver .env.example)."
        )
    return value or ""


def _get_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"'{key}' debe ser un numero entero, no '{raw}'.")


# --- Interfaz y ficheros -------------------------------------------------

WG_INTERFACE = _get("WG_INTERFACE", "wg0")
WG_CONF = _get("WG_CONF", f"/etc/wireguard/{WG_INTERFACE}.conf")
CLIENTS_DIR = _get("CLIENTS_DIR", "/opt/wg-manager/clients")
LOCK_FILE = _get("LOCK_FILE", "/run/lock/wg-manager.lock")

# --- Red -----------------------------------------------------------------

_subnet_raw = _get("WG_SUBNET", required=True)
try:
    WG_SUBNET = ipaddress.IPv4Network(_subnet_raw, strict=False)
except ValueError as exc:
    raise ConfigError(f"WG_SUBNET invalida ('{_subnet_raw}'): {exc}")

_server_ip_raw = _get("WG_SERVER_IP", str(next(WG_SUBNET.hosts())))
try:
    WG_SERVER_IP = ipaddress.IPv4Address(_server_ip_raw)
except ValueError as exc:
    raise ConfigError(f"WG_SERVER_IP invalida ('{_server_ip_raw}'): {exc}")

if WG_SERVER_IP not in WG_SUBNET:
    raise ConfigError(
        f"WG_SERVER_IP ({WG_SERVER_IP}) esta fuera de WG_SUBNET ({WG_SUBNET})."
    )

# Primer ultimo-octeto que se reparte a clientes.
CLIENT_IP_START = _get_int("CLIENT_IP_START", 2)

# --- Datos que se escriben en el .conf del cliente -----------------------

SERVER_ENDPOINT = _get("SERVER_ENDPOINT", required=True)
SERVER_PORT = _get_int("SERVER_PORT", 51820)

# Que rutas mete el cliente en el tunel. Por defecto solo la propia VPN
# (split tunnel): el resto del trafico del cliente sale por su red normal.
CLIENT_ALLOWED_IPS = _get("CLIENT_ALLOWED_IPS", str(WG_SUBNET))

# Vacio = no se escribe la linea DNS. Ojo: fijar un DNS con split tunnel
# manda TODAS las consultas del cliente por el tunel y suele romper la
# resolucion de nombres de su red local.
CLIENT_DNS = _get("CLIENT_DNS", "")

CLIENT_KEEPALIVE = _get_int("CLIENT_KEEPALIVE", 25)

# Mascara del Address del cliente. 32 es lo correcto; 24 se mantiene
# disponible por compatibilidad con despliegues antiguos.
CLIENT_ADDRESS_PREFIX = _get_int("CLIENT_ADDRESS_PREFIX", 32)
if CLIENT_ADDRESS_PREFIX not in (24, 32):
    raise ConfigError("CLIENT_ADDRESS_PREFIX solo admite 24 o 32.")

if not 1 <= SERVER_PORT <= 65535:
    raise ConfigError(f"SERVER_PORT fuera de rango: {SERVER_PORT}")

if not 0 <= CLIENT_KEEPALIVE <= 65535:
    raise ConfigError(f"CLIENT_KEEPALIVE fuera de rango: {CLIENT_KEEPALIVE}")


def summary() -> str:
    """Resumen legible, sin secretos, para la cabecera del menu."""
    origen = ENV_FILE or "(sin .env: valores por defecto y entorno)"
    return (
        f"interfaz {WG_INTERFACE} | red {WG_SUBNET} | "
        f"endpoint {SERVER_ENDPOINT}:{SERVER_PORT}\nconfig: {origen}"
    )
