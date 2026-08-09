# wg-manager

Gestor de clientes WireGuard desde terminal. Alta, baja, edición, QR y
estadísticas de tráfico, trabajando directamente sobre `wg0.conf` y
sincronizando en caliente con el kernel — sin cortar los túneles activos.

Sin dependencias de Python: solo la biblioteca estándar.

## Requisitos

- Python 3.11 o superior (usa `str | None` en anotaciones).
- `wireguard-tools` (`wg`, `wg-quick`).
- `qrencode`, solo si quieres mostrar códigos QR.
- Permisos de root: lee y escribe `/etc/wireguard/` y habla con el kernel.

```bash
sudo apt install wireguard-tools qrencode
```

## Instalación

```bash
git clone <repo> /opt/wg-manager
cd /opt/wg-manager
cp .env.example .env
chmod 600 .env
$EDITOR .env
sudo wg-manager
```

El `.env` se busca en este orden:

1. La ruta indicada en la variable de entorno `WG_MANAGER_ENV`
2. `/etc/wg-manager/.env`
3. El `.env` junto a `main.py`

Las variables ya presentes en el entorno tienen prioridad sobre el fichero,
lo que permite sobreescribir un valor puntual sin editar nada:

```bash
sudo -E WG_INTERFACE=wg1 python3 main.py
```

`sudo -E` conserva el entorno. Sin `-E`, `sudo` lo limpia y `WG_MANAGER_ENV`
se pierde.

## Configuración

Todos los valores están en `.env.example` con su explicación. Los tres que
casi siempre hay que tocar:

| Variable | Qué es |
|---|---|
| `WG_SUBNET` | Red de la VPN. Evita `10.0.x`, `10.8.x` y `10.10.x`: chocan con VPN corporativas, hoteles y routers 4G |
| `SERVER_ENDPOINT` | IP o dominio público por el que los clientes llegan al servidor |
| `CLIENT_ALLOWED_IPS` | Qué rutas mete el cliente en el túnel. Solo la subred = split tunnel |

## Cómo se comporta

- **Escritura atómica.** Fichero temporal y `os.replace`, nunca un `open("w")`
  que trunca antes de escribir. Un corte de luz a mitad no te deja sin VPN.
- **Respaldo y reversión.** Cada cambio deja un `wg0.conf.bak`. Si el kernel
  rechaza la nueva configuración, se restaura sola.
- **Un escritor a la vez.** `flock` sobre `LOCK_FILE`: dos ejecuciones
  simultáneas no corrompen el fichero.
- **Reutiliza direcciones.** Asigna la IP libre más baja de la subred, así que
  los huecos de clientes revocados se vuelven a usar.
- **Ve todos los peers**, también los añadidos a mano fuera de la herramienta;
  aparecen marcados como `[peer manual]` y no se les puede pisar la IP.
- **Los `.conf` de cliente se crean en 600** y se borran al revocar el acceso:
  contienen una llave privada.

## Tests

```bash
python3 -m unittest -v
```

18 pruebas sobre el parseo de `wg0.conf`, el reparto de direcciones, la
validación de alias y el borrado con respaldo. No tocan WireGuard ni el
kernel: trabajan sobre ficheros temporales.

## Notas de seguridad

- Las llaves privadas nunca pasan por la línea de comandos. `argv` es legible
  en `/proc/<pid>/cmdline` por cualquier usuario de la máquina.
- Ningún comando se ejecuta a través de una shell: todo va como lista de
  argumentos, así que un alias no puede inyectar comandos.
- Los alias se validan contra `^[A-Za-z0-9._-]{1,32}$`.
- **La llave privada del cliente se genera en el servidor.** Es lo que permite
  entregar el `.conf` y el QR ya hechos. Para clientes de alto valor, lo más
  seguro sigue siendo generar la llave en el propio dispositivo y registrar
  aquí solo la pública.

## Estructura

| Fichero | Responsabilidad |
|---|---|
| `config.py` | Carga y valida el `.env`. Falla al arrancar si algo no cuadra |
| `wg_crypto.py` | Ejecución de comandos y generación de llaves |
| `wg_network.py` | Cálculo de direcciones dentro de la subred |
| `wg_core.py` | Alta, baja, edición y parseo de `wg0.conf` |
| `main.py` | Menú interactivo |
