
# FénixManager

<div align="center">

  <a href="">![GitHub Lines Code](https://img.shields.io/tokei/lines/github/m1001-byte/fenixmanager?style=for-the-badge)</a>
  <a href="">![GitHub forks](https://img.shields.io/github/forks/M1001-byte/FenixManager?style=for-the-badge)</a>
  <a href="">![GitHub issues](https://img.shields.io/github/issues/M1001-byte/FenixManager?style=for-the-badge)</a>
  <a href="">![GitHub stars](https://img.shields.io/github/stars/M1001-byte/FenixManager?style=for-the-badge)</a>
  <a href="">![GitHUb License](https://img.shields.io/github/license/m1001-byte/fenixmanager?style=for-the-badge)</a>

  <a href="https://imgbb.com/"><img src="https://i.ibb.co/qBj4Pth/fenix-menu.png" alt="fenix-menu" border="0"></a>
</div>

## 💻 Requisitos
 * Ubuntu 18.04 LTS o superior.
 * Debian 9 o superior.

## 🚀 Instalacion

```bash
sudo apt-get update # Actualizar lista de paquetes
sudo apt-get upgrade -y # Actualizar paquetes
sudo apt-get install -y wget # Instalar wget
wget https://raw.githubusercontent.com/M1001-byte/FenixManager/master/install.bash -O /tmp/install-fenix.bash # Descargar instalador
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
    * badvpn udpgw
* Configuracion
    * Administrar Hitman ( Encargado de eliminar usuarios expirados,o que superen el número máximo de conexiones permitidas)
    * Administrar Firewall ( UFW )
        * Activas/Desactivar
        * Permitir/bloquear puertos
    * Cambiar zona horaria ( Disponibles solo las de habla-hispana )
    * Activar / Desactivar bloqueador de anuncios ( Misma lista de hosts que AdAway )
    * Bloquear / Desbloquear P2P ( Torrents, etc )
    * Cambiar ajustes de Fénix
        * Mostar / Ocultar Paneles
* Desinstalar FénixManager
    * Elimina todos los archivos/directorios creados por el script
    * Elimina todos los servicios instalados por el script ( dropbear,squid,etc )
    * Restaura el archivo ".bashrc" al estado original
    * Elimina la entrada "/bin/false" del archivo "/etc/shells" ( Agregada para el correcto funcionamiento de dropbear )

### **Y mas por venir :)**

## Contacto
**Unicos medios de contactos.**
  * **Telegram: [@Mathiue1001](https://t.me/Mathiue1001)**
  * **Telegram: [@M1001_byte](https://t.me/M1001_byte)**
  * **Canal de Telegram: [@ScriptFenixManager](https://t.me/ScriptFenixManager)**

## 📝 Licencia
[MIT](https://choosealicense.com/licenses/mit/)
