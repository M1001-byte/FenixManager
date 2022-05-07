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
 * Arquitectura de 64 bits.
## 🚀 Instalacion

```bash
sudo apt-get update # Actualizar lista de paquetes
sudo apt-get upgrade # Actualizar paquetes
sudo apt-get install -y wget # Instalar wget
wget https://raw.githubusercontent.com/M1001-byte/FenixManager/dev/install.bash -O /tmp/install-fenix.bash # Descargar instalador
sudo bash /tmp/install-fenix.bash # Instalar
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

### **Y mas por venir :)**

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
<a href="https://ibb.co/5KYCymn"><img src="https://i.ibb.co/jJVq2mW/cfg-menu.png" alt="cfg-menu" border="0"></a>
***
<a href="https://ibb.co/9cspNTq"><img src="https://i.ibb.co/vVZcHPJ/fenix-settings.png" alt="Ajustes FenixManager" border="0"></a>
***
<a href="https://ibb.co/m4xRtDx"><img src="https://i.ibb.co/0rwnZDw/menu-proto.png" alt="menu-proto" border="0"></a>

## Contribuir
1. Bifurcar este  repositorio
2. Crea tu rama de característica (`git checkout -b feature/CaracteristicaIncreible`)
3. Guardar los cambios  (`git commit -m 'Agregadas funciones increibles'`)
4. Subir los cambios hacia la rama (`git push origin feature/CaracteristicaIncreible`)
5. Abrir una solicitud pull

## Contacto
**Unicos medios de contactos**
  * **Telegram: [@Mathiue1001](https://t.me/Mathiue1001)**
  * **Telegram: [@M1001_byte](https://t.me/M1001_byte)**

## 📝 Licencia
[MIT](https://choosealicense.com/licenses/mit/)
