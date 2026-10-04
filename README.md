# SISTEMA BASA V7 - AUDIT INTELLIGENCE USA (v7.0 FINAL)
**Repositorio GitHub:** [https://github.com/balderasantosyasociados/BASA_V7-system-](https://github.com/balderasantosyasociados/BASA_V7-system-)  
**Ruta de Prueba Gratuita:** [https://audit-intelligence-usa.com/trial](https://audit-intelligence-usa.com/trial)  
**Titular:** Pedro Baldera | **BHD León:** 08694150021 | **WhatsApp:** +1 829-771-7390

---

## 📌 Novedades Integradas en esta Versión

1. **Corrección completa de `app.py`**:
   - Resuelto el conflicto de decorators entre `/api/auth/register` y `/trial`.
   - Creada la plantilla interactiva `TRIAL_HTML` incrustada para renderizar el portal de 3 días en `https://audit-intelligence-usa.com/trial`.
   - Implementado el middleware de bloqueo `@requiere_trial_o_pago`:
     $$\text{Días Transcurridos} = \frac{\text{Fecha Actual} - \text{Fecha Registro}}{86400}$$
     - Si $\le 3$ días: Acceso permitido.
     - Si $> 3$ días y `estado_pago == False`: Bloqueo inmediato y redirección a pago BHD.
2. **Cloudflare Tunnel Automático**:
   - Archivo `config.yml` configurado con `ingress` para `audit-intelligence-usa.com/trial` y puerto 5000.
   - Script `setup_tunnel.sh` que instala cloudflared, crea el túnel y añade los registros DNS en Cloudflare automáticamente.
3. **Persistencia en `storage/clientes.json`**:
   - Guarda `email`, `fecha_registro`, `plan` y `estado_pago`.
4. **Facturación y Notificación por WhatsApp**:
   - Integración directa con ReportLab para generar factura PDF BHD León y notificar a Pedro Baldera al +1 829-771-7390.

---

## 🚀 Cómo Iniciar en 3 Pasos

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Iniciar la aplicación
python app.py

# 3. En otra terminal, activar el túnel seguro:
chmod +x setup_tunnel.sh
./setup_tunnel.sh
```

¡Tu sistema quedará en vivo en **https://audit-intelligence-usa.com/trial**!
