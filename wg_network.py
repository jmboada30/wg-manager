"""
Calculo de direcciones dentro de la red de la VPN.

Todo se resuelve contra la subred del .env, no contra un prefijo escrito a
mano: la version anterior tenia '10.8.0.' fijo en un regex y en cualquier otra
red repartia direcciones fuera de rango.
"""

import ipaddress
import re

import config

# Captura cualquier direccion listada en AllowedIPs, con o sin mascara,
# incluidas las lineas con varias rutas separadas por comas.
_ALLOWED_IPS_RE = re.compile(r"^\s*AllowedIPs\s*=\s*(.+)$", re.MULTILINE)


def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def assigned_ips(conf_text: str) -> set[ipaddress.IPv4Address]:
    """Direcciones de la subred ya presentes en el fichero de configuracion."""
    usadas: set[ipaddress.IPv4Address] = set()
    for linea in _ALLOWED_IPS_RE.findall(conf_text):
        for trozo in linea.split(","):
            trozo = trozo.strip()
            if not trozo:
                continue
            try:
                red = ipaddress.IPv4Network(trozo, strict=False)
            except ValueError:
                continue
            # Solo interesan las asignaciones puntuales dentro de nuestra red;
            # una ruta como 192.168.50.0/24 no consume una IP de cliente.
            if red.prefixlen == 32 and red.network_address in config.WG_SUBNET:
                usadas.add(red.network_address)
    return usadas


def is_ip_available(ip: str, conf_text: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip.strip())
    except (ipaddress.AddressValueError, ValueError):
        return False
    if addr not in config.WG_SUBNET or addr == config.WG_SERVER_IP:
        return False
    return addr not in assigned_ips(conf_text)


def next_free_ip(conf_text: str) -> str:
    """
    Primera direccion libre de la subred, empezando por CLIENT_IP_START.

    Reutiliza los huecos que dejan los clientes revocados. La version anterior
    hacia max(octeto)+1, de modo que agotaba el rango sin volver a usar nunca
    una direccion liberada.
    """
    usadas = assigned_ips(conf_text)
    for host in config.WG_SUBNET.hosts():
        if int(host) & 0xFF < config.CLIENT_IP_START:
            continue
        if host == config.WG_SERVER_IP or host in usadas:
            continue
        return str(host)
    raise ValueError(
        f"No quedan direcciones libres en {config.WG_SUBNET} "
        f"(inicio en .{config.CLIENT_IP_START})."
    )
