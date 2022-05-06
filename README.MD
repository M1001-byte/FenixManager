# FénixManager

![GitHub Lines Code](https://img.shields.io/tokei/lines/github/m1001-byte/fenixmanager?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/M1001-byte/FenixManager?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/M1001-byte/FenixManager?style=for-the-badge)
![GitHub stars](https://img.shields.io/github/stars/M1001-byte/FenixManager?style=for-the-badge)
![GitHUb License](https://img.shields.io/github/license/m1001-byte/fenixmanager?style=for-the-badge)


<p align="center">
<a href="https://imgbb.com/"><img src="https://i.ibb.co/PT5Bcvg/fenixmanager.png" alt="fenixmanager" border="0"></a>
</p>

## 💻 Requisitos
 * Ubuntu 18.04 LTS o superior.
 * Debian 9 o superior.

## 🚀 Instalacion

```bash
wget https://raw.githubusercontent.com/M1001-byte/FenixManager/dev/install.bash -O /tmp/install-fenix.bash
sudo bash /tmp/install-fenix.bash
```
## 🧉 Características

* Administrar usuarios ssh
    * Agregar
    * Eliminar 
    * Editar
    * Crear / Restaurar una copia de seguridad
* Menú de instalación
    * Dropbear
    * Squid-proxy
    * Stunnel
    * Slowdns
    * Shadowsocks-libev ( incluye plug-ins )
    * Openvpn
    * V2ray / X-UI
    * Un simple proxy de redireccionamiento de puertos. ( Escrito en python3 )
* Configuracion
    * Administrar Hitman ( Encargado de eliminar usuarios expirados,o que superen el número máximo de conexiones permitidas)
    * Administrar Firewall ( UFW )
        * Activas/Desactivar
        * Permitir/bloquear puertos
    * Cambiar zona horaria ( Disponibles solo las de habla-hispana )
    * Activar / Desactivar bloqueador de anuncios ( Lista de host bloqueados desde AdAway )
    * Bloquear / Desbloquear P2P ( Torrents, etc )
    * Cambiar ajustes de Fénix
        * Mostar / Ocultar Paneles

## ✏️ Características Futuras
 - [ ] Administrar vps desde un bot de Telegram
 - [ ] Panel de administracion via web

## 📸 Screenshots
**Si la  visualización del script no es correcta: es recomendable reducir el tamaño de la fuente de tu terminal.**
***
<a href="https://imgbb.com/"><img src="https://i.ibb.co/jWSb49Q/adm-ssh.png" alt="Administrar usuarios ssh" border="0"></a>
***
<a href="https://imgbb.com/"><img src="https://i.ibb.co/2cgcgHS/py-socks.png" alt="Proxy forwarding" border="0"></a>
***
<a href="https://imgbb.com/"><img src="https://i.ibb.co/myY2dMx/cfg-menu.png" alt="Configur**aciones" border="0"></a><a href="https://imgbb.com/"><img src="https://i.ibb.co/9qP0z0s/cfg-setting-fenix.png" alt="FenixManafer Ajustes" border="0"></a>
***
<a href="https://imgbb.com/"><img src="https://i.ibb.co/LpSn9jh/cfg-proto.png" alt="Menu de protocolos" border="0"></a>

## Contribuir
1. Bifurcar este  repositorio
2. Crea tu rama de característica (`git checkout -b feature/CaracteristicaIncreible`)
3. Guardar los cambios  (`git commit -m 'Agregadas funciones increibles'`)
4. Subir los cambios hacia la rama (`git push origin feature/CaracteristicaIncreible`)
5. Abrir una solicitud pull

## 📝 Licencia
[MIT](https://choosealicense.com/licenses/mit/)
