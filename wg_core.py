"""
Alta, baja, edicion y consulta de clientes sobre el fichero de WireGuard.

Garantias del modulo:
  - Un solo proceso escribe a la vez (flock sobre config.LOCK_FILE).
  - La escritura es atomica: fichero temporal + os.replace, nunca un
    open(..., "w") que trunca antes de escribir.
  - Cada escritura deja un .bak, y si la sincronizacion con el kernel falla
    se restaura ese .bak automaticamente.
  - Los .conf de cliente se crean en 600: contienen una llave privada.
"""

import contextlib
import fcntl
import ipaddress
import os
import re
import shutil

import config
from wg_crypto import WgError, generate_keys, get_server_pubkey, run, sync_wireguard_hot
from wg_network import is_ip_available, next_free_ip

# Alias que se puede usar como nombre de fichero sin sorpresas. Evita
# ademas la inyeccion por interpolacion en cualquier ruta derivada de el.
ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")

_CLIENT_TAG = "# Client:"


class CoreError(Exception):
    """Error de operacion sobre clientes."""


def validate_alias(alias: str) -> str:
    alias = (alias or "").strip()
    if not ALIAS_RE.match(alias):
        raise CoreError(
            "Alias invalido. Solo letras, numeros, punto, guion y guion bajo "
            "(maximo 32 caracteres). Ejemplos: 'equipo-oficina', 'movil.ventas'."
        )
    return alias


@contextlib.contextmanager
def _lock():
    """Exclusion mutua entre ejecuciones concurrentes de la herramienta."""
    directorio = os.path.dirname(config.LOCK_FILE)
    if directorio:
        os.makedirs(directorio, exist_ok=True)
    fh = open(config.LOCK_FILE, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def read_conf() -> str:
    try:
        with open(config.WG_CONF, "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        raise CoreError(f"No existe {config.WG_CONF}.")
    except PermissionError:
        raise CoreError(f"Sin permiso para leer {config.WG_CONF}. Ejecuta con sudo.")


def _write_conf_atomic(text: str) -> str:
    """Escribe la configuracion de forma atomica. Devuelve la ruta del .bak."""
    destino = config.WG_CONF
    backup = destino + ".bak"
    if os.path.exists(destino):
        shutil.copy2(destino, backup)

    tmp = destino + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, destino)
    return backup


def _restore(backup: str) -> None:
    if os.path.exists(backup):
        shutil.copy2(backup, config.WG_CONF)


def _apply(text: str) -> None:
    """Escribe y sincroniza. Si el kernel rechaza el cambio, deshace."""
    backup = _write_conf_atomic(text)
    try:
        sync_wireguard_hot()
    except WgError:
        _restore(backup)
        raise


# --- Lectura de clientes -------------------------------------------------


def parse_clients(conf_text: str | None = None) -> tuple[list[str], list[dict]]:
    """
    Devuelve (lineas, clientes).

    Reconoce cualquier bloque [Peer], lleve o no la marca '# Client:'. La
    version anterior solo veia los suyos, asi que un peer anadido a mano era
    invisible y su IP podia reasignarse a otro cliente.
    """
    text = conf_text if conf_text is not None else read_conf()
    lines = text.splitlines(keepends=True)

    cabeceras = [i for i, l in enumerate(lines) if l.strip().startswith("[")]
    clientes: list[dict] = []

    for pos, i in enumerate(cabeceras):
        if lines[i].strip().lower() != "[peer]":
            continue

        siguiente = cabeceras[pos + 1] if pos + 1 < len(cabeceras) else len(lines)

        # Los comentarios pegados por encima pertenecen a este bloque.
        inicio = i
        while inicio > 0 and lines[inicio - 1].strip().startswith("#"):
            inicio -= 1

        # Los comentarios y blancos pegados al bloque siguiente son suyos.
        fin = siguiente - 1
        while fin > i and (
            lines[fin].strip() == "" or lines[fin].strip().startswith("#")
        ):
            fin -= 1

        bloque = "".join(lines[inicio : fin + 1])

        alias, gestionado = _extraer_alias(lines, inicio, i, fin)
        pubkey = _extraer_valor(bloque, "PublicKey") or ""
        ip = _extraer_ip(bloque)

        clientes.append(
            {
                "alias": alias,
                "ip": ip,
                "pubkey": pubkey,
                "start_idx": inicio,
                "end_idx": fin,
                "managed": gestionado,
            }
        )

    return lines, clientes


def _extraer_alias(lines: list[str], inicio: int, header: int, fin: int) -> tuple[str, bool]:
    """
    Busca el nombre del peer. El comentario puede estar encima de [Peer]
    (formato de esta herramienta) o dentro del bloque, que es como quedan
    los peers escritos a mano.
    """
    # 1. Marca propia de la herramienta, en cualquier posicion del bloque.
    for idx in range(inicio, fin + 1):
        texto = lines[idx].strip()
        if texto.startswith(_CLIENT_TAG):
            return texto[len(_CLIENT_TAG) :].strip(), True

    # 2. Cualquier comentario: primero encima de la cabecera, luego dentro.
    for rango in (range(inicio, header), range(header + 1, fin + 1)):
        for idx in rango:
            texto = lines[idx].strip()
            if texto.startswith("#"):
                etiqueta = texto.lstrip("#").strip()
                if etiqueta:
                    return etiqueta, False

    return "(sin alias)", False


def _extraer_valor(bloque: str, clave: str) -> str | None:
    m = re.search(rf"^\s*{clave}\s*=\s*(.+)$", bloque, re.MULTILINE)
    return m.group(1).strip() if m else None


def _extraer_ip(bloque: str) -> str:
    valor = _extraer_valor(bloque, "AllowedIPs") or ""
    for trozo in valor.split(","):
        trozo = trozo.strip()
        try:
            red = ipaddress.IPv4Network(trozo, strict=False)
        except ValueError:
            continue
        if red.prefixlen == 32 and red.network_address in config.WG_SUBNET:
            return str(red.network_address)
    return ""


# --- Ficheros de cliente -------------------------------------------------


def client_path(alias: str) -> str:
    return os.path.join(config.CLIENTS_DIR, f"{alias}.conf")


def _render_client_conf(priv: str, psk: str, ip: str, srv_pub: str) -> str:
    lineas = [
        "[Interface]",
        f"PrivateKey = {priv}",
        f"Address = {ip}/{config.CLIENT_ADDRESS_PREFIX}",
    ]
    if config.CLIENT_DNS:
        lineas.append(f"DNS = {config.CLIENT_DNS}")
    lineas += [
        "",
        "[Peer]",
        f"PublicKey = {srv_pub}",
        f"PresharedKey = {psk}",
        f"Endpoint = {config.SERVER_ENDPOINT}:{config.SERVER_PORT}",
        f"AllowedIPs = {config.CLIENT_ALLOWED_IPS}",
        f"PersistentKeepalive = {config.CLIENT_KEEPALIVE}",
        "",
    ]
    return "\n".join(lineas)


def _write_client_file(alias: str, contenido: str) -> str:
    os.makedirs(config.CLIENTS_DIR, mode=0o700, exist_ok=True)
    os.chmod(config.CLIENTS_DIR, 0o700)
    ruta = client_path(alias)
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(contenido)
    return ruta


# --- Operaciones ---------------------------------------------------------


def create_client(alias: str) -> dict:
    alias = validate_alias(alias)

    with _lock():
        texto = read_conf()
        _, clientes = parse_clients(texto)

        if any(c["alias"] == alias for c in clientes):
            raise CoreError(f"Ya existe un cliente con el alias '{alias}'.")
        if os.path.exists(client_path(alias)):
            raise CoreError(
                f"Ya hay un fichero {client_path(alias)}. "
                f"Borralo o usa otro alias."
            )

        ip = next_free_ip(texto)
        srv_pub = get_server_pubkey()
        priv, pub, psk = generate_keys()

        bloque = (
            f"\n{_CLIENT_TAG} {alias}\n"
            f"[Peer]\n"
            f"PublicKey = {pub}\n"
            f"PresharedKey = {psk}\n"
            f"AllowedIPs = {ip}/32\n"
        )
        if not texto.endswith("\n"):
            texto += "\n"

        _apply(texto + bloque)
        ruta = _write_client_file(alias, _render_client_conf(priv, psk, ip, srv_pub))

    return {"alias": alias, "ip": ip, "pubkey": pub, "path": ruta}


def edit_client(index: int, new_alias: str, new_ip: str) -> dict:
    if new_alias:
        new_alias = validate_alias(new_alias)

    with _lock():
        texto = read_conf()
        lines, clientes = parse_clients(texto)
        if not 0 <= index < len(clientes):
            raise CoreError("Indice de cliente fuera de rango.")

        objetivo = clientes[index]
        alias_viejo, ip_vieja = objetivo["alias"], objetivo["ip"]

        if new_alias and any(
            c["alias"] == new_alias for i, c in enumerate(clientes) if i != index
        ):
            raise CoreError(f"Ya existe otro cliente con el alias '{new_alias}'.")

        if new_ip:
            if not is_ip_available(new_ip, texto):
                raise CoreError(
                    f"La IP {new_ip} no es valida, esta fuera de {config.WG_SUBNET} "
                    f"o ya esta en uso."
                )

        # Comentario de alias: se crea si el peer no lo tenia (peer manual).
        if new_alias:
            marca = f"{_CLIENT_TAG} {new_alias}\n"
            for i in range(objetivo["start_idx"], objetivo["end_idx"] + 1):
                if lines[i].strip().startswith(_CLIENT_TAG):
                    lines[i] = marca
                    break
            else:
                lines.insert(objetivo["start_idx"], marca)
                objetivo["end_idx"] += 1

        if new_ip:
            for i in range(objetivo["start_idx"], objetivo["end_idx"] + 1):
                if lines[i].strip().startswith("AllowedIPs"):
                    lines[i] = f"AllowedIPs = {new_ip}/32\n"
                    break

        _apply("".join(lines))

        alias_final = new_alias or alias_viejo
        ip_final = new_ip or ip_vieja

        # El .conf del cliente solo se toca si existe: un peer creado a mano
        # no tiene fichero y no hay nada que reescribir.
        viejo = client_path(alias_viejo)
        if os.path.exists(viejo):
            with open(viejo, "r", encoding="utf-8") as fh:
                datos = fh.read()
            if new_ip:
                datos = re.sub(
                    r"Address\s*=\s*[0-9.]+/\d+",
                    f"Address = {ip_final}/{config.CLIENT_ADDRESS_PREFIX}",
                    datos,
                )
            _write_client_file(alias_final, datos)
            if alias_final != alias_viejo:
                os.remove(viejo)

    return {"alias": alias_final, "ip": ip_final}


def delete_client(index: int) -> dict:
    with _lock():
        texto = read_conf()
        lines, clientes = parse_clients(texto)
        if not 0 <= index < len(clientes):
            raise CoreError("Indice de cliente fuera de rango.")

        objetivo = clientes[index]
        inicio, fin = objetivo["start_idx"], objetivo["end_idx"]
        while inicio > 0 and lines[inicio - 1].strip() == "":
            inicio -= 1

        del lines[inicio : fin + 1]
        _apply("".join(lines))

        # El fichero del cliente guarda su llave privada: se borra con el peer.
        ruta = client_path(objetivo["alias"])
        borrado = False
        if os.path.exists(ruta):
            os.remove(ruta)
            borrado = True

    return {"alias": objetivo["alias"], "conf_borrado": borrado}


def show_qr(alias: str) -> bool:
    ruta = client_path(alias)
    if not os.path.exists(ruta):
        print(f"-> No hay fichero de configuracion para '{alias}' ({ruta}).")
        print("   Los peers creados a mano no tienen .conf que mostrar.")
        return False

    with open(ruta, "r", encoding="utf-8") as fh:
        contenido = fh.read()

    print(f"\n--- Escanea este QR desde el movil para '{alias}' ---")
    # El contenido va por stdin: la ruta no se interpola en ninguna shell.
    print(run(["qrencode", "-t", "ANSIUTF8"], stdin=contenido))
    print("------------------------------------------------------")
    return True
