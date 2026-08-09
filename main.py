#!/usr/bin/env python3
"""
wg-manager: gestor de clientes WireGuard desde terminal.

Uso: sudo -E python3 main.py
"""

import os
import subprocess
import sys
import time

try:
    import config
except Exception as exc:  # ConfigError aun no existe si el import falla
    print(f"\n[CONFIG] {exc}\n", file=sys.stderr)
    sys.exit(2)

from wg_core import (
    CoreError,
    create_client,
    delete_client,
    edit_client,
    parse_clients,
    show_qr,
)
from wg_crypto import WgError, run
from wg_network import is_ip_available, is_valid_ipv4


def format_bytes(size: int) -> str:
    valor = float(size)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if valor < 1024.0:
            return f"{valor:.2f} {unit}"
        valor /= 1024.0
    return f"{valor:.2f} PB"


def time_ago(ts: int) -> str:
    if ts == 0:
        return "Nunca"
    diff = int(time.time()) - ts
    if diff < 60:
        return f"Hace {diff} segundos"
    if diff < 3600:
        return f"Hace {diff // 60} minutos"
    if diff < 86400:
        return f"Hace {diff // 3600} horas"
    return f"Hace {diff // 86400} dias"


def show_client_stats(alias: str, ip: str) -> None:
    dump = run(["wg", "show", config.WG_INTERFACE, "dump"])
    for line in dump.split("\n")[1:]:
        parts = line.split("\t")
        if len(parts) >= 8 and f"{ip}/32" in parts[3]:
            print(f"\n=== ESTATUS DE RED: {alias} ===")
            print(f"IP Asignada      : {ip}")
            print(f"Llave Publica    : {parts[0]}")
            print(f"Ultimo Handshake : {time_ago(int(parts[4]))}")
            print(f"Trafico Rx (Desc): {format_bytes(int(parts[5]))}")
            print(f"Trafico Tx (Sub) : {format_bytes(int(parts[6]))}")
            print("===================================")
            return
    print(f"\n-> No hay datos activos en el kernel para {alias} ({ip}).")


def select_client(action: str) -> tuple[int, str, str]:
    _, clients = parse_clients()
    if not clients:
        print(f"\n-> No hay peers registrados en {config.WG_CONF}.")
        return -1, "", ""

    lines = [f"--- Clientes actuales (para {action}) ---"]
    for i, c in enumerate(clients):
        marca = "" if c["managed"] else "  [peer manual]"
        lines.append(f"[{i}] {c['alias']} (IP: {c['ip'] or 'sin IP en la subred'}){marca}")
    lines.append("\n(Pulsa 'q' para salir de esta lista)")

    subprocess.run(["less"], input="\n".join(lines), text=True)

    try:
        idx = int(input(f"\nNumero del cliente a {action} (-1 para cancelar): ").strip())
    except ValueError:
        idx = -1
    if 0 <= idx < len(clients):
        return idx, clients[idx]["alias"], clients[idx]["ip"]
    print("-> Accion cancelada o indice invalido.")
    return -1, "", ""


def require_root() -> None:
    if os.geteuid() != 0:
        print(
            "\n[ERROR] wg-manager necesita privilegios de root para leer "
            f"{config.WG_CONF} y hablar con el kernel.\n"
            "        Ejecuta:  sudo -E python3 main.py\n",
            file=sys.stderr,
        )
        sys.exit(1)


def menu() -> None:
    while True:
        print("\n=== GESTOR VPN WIREGUARD ===")
        print(config.summary())
        print("\n1. Ver estatus de un cliente")
        print("2. Crear nueva conexion")
        print("3. Editar conexion")
        print("4. Borrar/Revocar conexion")
        print("5. Mostrar QR de cliente existente")
        print("6. Salir")

        opcion = input("\nElige una opcion [1-6]: ").strip()

        try:
            if opcion == "1":
                idx, alias, ip = select_client("ver estatus")
                if idx != -1:
                    show_client_stats(alias, ip)
                input("\nPulsa Enter para volver...")

            elif opcion == "2":
                alias = input("Alias del cliente (ej: equipo-oficina): ")
                info = create_client(alias)
                print(f"\n[OK] Cliente '{info['alias']}' creado. IP: {info['ip']}")
                print(f"     Configuracion: {info['path']}")
                show_qr(info["alias"])
                input("\nPulsa Enter para volver...")

            elif opcion == "3":
                idx, _, _ = select_client("editar")
                if idx == -1:
                    continue
                print("\n(Deja en blanco lo que no quieras cambiar)")
                new_alias = input("Nuevo alias: ").strip()
                new_ip = input(f"Nueva IP (dentro de {config.WG_SUBNET}): ").strip()
                if not new_alias and not new_ip:
                    print("-> Nada que cambiar.")
                    continue
                if new_ip and not is_valid_ipv4(new_ip):
                    print("-> Error: la IP no tiene formato valido.")
                    continue
                info = edit_client(idx, new_alias, new_ip)
                print(f"\n[OK] Cliente '{info['alias']}' actualizado (IP: {info['ip']}).")

            elif opcion == "4":
                idx, alias, _ = select_client("borrar")
                if idx == -1:
                    continue
                if input(f"¿Revocar el acceso de '{alias}'? (s/N): ").strip().lower() != "s":
                    print("-> Cancelado.")
                    continue
                info = delete_client(idx)
                extra = "" if info["conf_borrado"] else " (no tenia fichero .conf)"
                print(f"\n[OK] Acceso de '{info['alias']}' revocado{extra}.")

            elif opcion == "5":
                idx, alias, _ = select_client("mostrar QR")
                if idx != -1:
                    show_qr(alias)
                input("\nPulsa Enter para volver...")

            elif opcion == "6":
                sys.exit(0)

            else:
                print("-> Opcion no reconocida.")

        except (CoreError, WgError) as exc:
            print(f"\n[ERROR] {exc}")
            input("\nPulsa Enter para volver...")
        except KeyboardInterrupt:
            print("\n-> Operacion interrumpida.")


if __name__ == "__main__":
    require_root()
    try:
        menu()
    except KeyboardInterrupt:
        print()
        sys.exit(0)
