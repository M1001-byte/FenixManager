# FenixManager

![GitHub Lines Code](https://img.shields.io/tokei/lines/github/m1001-byte/fenixmanager?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/M1001-byte/FenixManager?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/M1001-byte/FenixManager?style=for-the-badge)
![GitHub stars](https://img.shields.io/github/stars/M1001-byte/FenixManager?style=for-the-badge)
[![MIT License](https://img.shields.io/github/license/M1001-byte/FenixManager?style=for-the-badge)](./LICENSE)

<p align="center">
<a href="https://imgbb.com/"><img src="https://i.ibb.co/PT5Bcvg/fenixmanager.png" alt="fenixmanager" border="0"></a>
</p>

## 🚀 Instalacion

```bash
wget https://raw.githubusercontent.com/M1001-byte/FenixManager/main/install.bash -o /tmp/install-fenix.bash
sudo bash /tmp/install.bash
```
## 🧉 Caracteristicas

* Administrar usuarios ssh
    * Agregar
    * Eliminar 
    * Editar
    * Crear/Restaurar una copia de seguridad
* Menu de instalacion
    * Dropbear
    * Squid-proxy
    * Stunnel
    * Slowdns
    * Shadowsocks-libev ( incluye plugins )
    * Openvpn
    * V2ray / X-UI
    * Un simple proxy de redireccionamiento de puertos. ( Escrito en python3 )
* Configuracion
    * Administrar Hitman ( Encargado de eliminar usuarios expirados,o que superen el numero maximo de conexiones permitidas)
    * Administrar Firewall ( UFW )
        * Activas/Desactivar
        * Permitir/bloquear puertos
    * Cambiar zona horaria ( Disponibles solo las de habla-hispana )
    * Activar/Desactivar bloqueador de anuncios ( Lista de host bloqueados desde AdAway )
    * Cambiar ajustes de Fenix
        * Mostar / Ocultar Paneles

## ✏️ Caracteristicas Futuras
 - [ ] El redireccionamiento atravez del proxy, reescribirlo usando Golang
 - [ ] Administrar vps desde un bot de Telegram
 - [ ] Panel de administracion via web


## Contribuir

1. Bifurcar este  repositorio
2. Crea tu rama de caracteristica (`git checkout -b feature/CaracteristicaIncreible`)
3. Guardar los cambios  (`git commit -m 'Agregadas funciones increibles'`)
4. Subir los cambios hacia la rama (`git push origin feature/CaracteristicaIncreible`)
5. Abrir una solicitud pull

## 📝 Licencia
[MIT](https://choosealicense.com/licenses/mit/)
