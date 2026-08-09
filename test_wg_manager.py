#!/usr/bin/env python3
"""
Pruebas de wg-manager. Solo biblioteca estandar:

    python3 -m unittest -v

No tocan WireGuard ni el kernel: trabajan sobre ficheros temporales y
sustituyen la sincronizacion por una funcion vacia.
"""

import os
import tempfile
import unittest

# La configuracion se valida al importarse, asi que hay que fijarla antes.
os.environ.setdefault("WG_SUBNET", "10.0.0.0/24")
os.environ.setdefault("WG_SERVER_IP", "10.0.0.1")
os.environ.setdefault("CLIENT_IP_START", "11")
os.environ.setdefault("SERVER_ENDPOINT", "vpn.ejemplo.com")
os.environ.setdefault("SERVER_PORT", "51820")

import config  # noqa: E402
import wg_core  # noqa: E402
import wg_network  # noqa: E402

# Mezcla deliberada de los dos formatos: un peer escrito a mano, con el
# comentario dentro del bloque, y uno creado por la herramienta.
CONF_EJEMPLO = """[Interface]
Address    = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr=

[Peer]
# Portatil de guardia
PublicKey    = Uq2MwzJl6fxu/oHnKG8Gig/0orJzqQLV+vvTVZhBQ1g=
PresharedKey = 1111111111111111111111111111111111111111111=
AllowedIPs   = 10.0.0.11/32

# Client: movil.ventas
[Peer]
PublicKey = 2222222222222222222222222222222222222222222=
PresharedKey = 3333333333333333333333333333333333333333333=
AllowedIPs = 10.0.0.13/32
"""


class BaseConf(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".conf", delete=False, encoding="utf-8"
        )
        self.tmp.write(CONF_EJEMPLO)
        self.tmp.close()
        self._conf_original = config.WG_CONF
        config.WG_CONF = self.tmp.name
        # Ni kernel ni wg en las pruebas.
        self._sync_original = wg_core.sync_wireguard_hot
        wg_core.sync_wireguard_hot = lambda *a, **k: None

    def tearDown(self):
        config.WG_CONF = self._conf_original
        wg_core.sync_wireguard_hot = self._sync_original
        for sufijo in ("", ".bak", ".tmp"):
            ruta = self.tmp.name + sufijo
            if os.path.exists(ruta):
                os.remove(ruta)


class TestParseo(BaseConf):
    def test_detecta_ambos_formatos_de_peer(self):
        _, clientes = wg_core.parse_clients()
        self.assertEqual(len(clientes), 2)

    def test_alias_de_peer_manual_va_dentro_del_bloque(self):
        _, clientes = wg_core.parse_clients()
        self.assertEqual(clientes[0]["alias"], "Portatil de guardia")
        self.assertFalse(clientes[0]["managed"])

    def test_alias_de_peer_gestionado(self):
        _, clientes = wg_core.parse_clients()
        self.assertEqual(clientes[1]["alias"], "movil.ventas")
        self.assertTrue(clientes[1]["managed"])

    def test_extrae_las_ips(self):
        _, clientes = wg_core.parse_clients()
        self.assertEqual(
            [c["ip"] for c in clientes], ["10.0.0.11", "10.0.0.13"]
        )


class TestDirecciones(BaseConf):
    def test_reutiliza_el_hueco_libre(self):
        # Con .11 y .13 ocupadas, la siguiente debe ser .12, no .14.
        self.assertEqual(wg_network.next_free_ip(CONF_EJEMPLO), "10.0.0.12")

    def test_ip_ocupada_no_esta_disponible(self):
        self.assertFalse(wg_network.is_ip_available("10.0.0.13", CONF_EJEMPLO))

    def test_ip_del_servidor_no_se_reparte(self):
        self.assertFalse(wg_network.is_ip_available("10.0.0.1", CONF_EJEMPLO))

    def test_ip_fuera_de_la_subred(self):
        self.assertFalse(wg_network.is_ip_available("10.99.0.5", CONF_EJEMPLO))

    def test_una_ruta_de_red_no_consume_direccion(self):
        # Un AllowedIPs con /24 es una ruta, no la IP de un cliente.
        texto = CONF_EJEMPLO + "\n[Peer]\nAllowedIPs = 10.0.0.0/24\n"
        self.assertNotIn("10.0.0.0", [str(x) for x in wg_network.assigned_ips(texto)])


class TestAlias(unittest.TestCase):
    def test_acepta_alias_normales(self):
        for alias in ("equipo-oficina", "movil.ventas", "pc_01", "A1"):
            self.assertEqual(wg_core.validate_alias(alias), alias)

    def test_rechaza_metacaracteres_de_shell(self):
        for alias in ("pc; reboot", "a$(id)", "../../etc/passwd", "a b", "a|b"):
            with self.assertRaises(wg_core.CoreError):
                wg_core.validate_alias(alias)

    def test_rechaza_vacio_y_demasiado_largo(self):
        for alias in ("", "   ", "x" * 33):
            with self.assertRaises(wg_core.CoreError):
                wg_core.validate_alias(alias)


class TestBorrado(BaseConf):
    def test_borra_el_bloque_y_deja_respaldo(self):
        wg_core.delete_client(1)
        _, restantes = wg_core.parse_clients()
        self.assertEqual([c["alias"] for c in restantes], ["Portatil de guardia"])
        self.assertTrue(os.path.exists(config.WG_CONF + ".bak"))

    def test_el_respaldo_conserva_el_contenido_previo(self):
        wg_core.delete_client(1)
        with open(config.WG_CONF + ".bak", encoding="utf-8") as fh:
            self.assertIn("movil.ventas", fh.read())

    def test_indice_fuera_de_rango(self):
        with self.assertRaises(wg_core.CoreError):
            wg_core.delete_client(99)


class TestEdicion(BaseConf):
    def test_renombrar_marca_el_peer_como_gestionado(self):
        # Un peer manual pasa a llevar la marca de la herramienta.
        wg_core.edit_client(0, "portatil-guardia", "")
        _, clientes = wg_core.parse_clients()
        self.assertEqual(clientes[0]["alias"], "portatil-guardia")
        self.assertTrue(clientes[0]["managed"])

    def test_cambiar_a_ip_ocupada_falla(self):
        with self.assertRaises(wg_core.CoreError):
            wg_core.edit_client(0, "", "10.0.0.13")

    def test_cambiar_ip_actualiza_el_bloque(self):
        wg_core.edit_client(0, "", "10.0.0.20")
        _, clientes = wg_core.parse_clients()
        self.assertEqual(clientes[0]["ip"], "10.0.0.20")


if __name__ == "__main__":
    unittest.main(verbosity=2)
