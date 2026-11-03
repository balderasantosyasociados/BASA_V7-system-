# -*- coding: utf-8 -*-
"""
================================================================================
BASA FORENSIC INTELLIGENCE - ENTERPRISE SUITE (EDICIÓN BIG 4)
Versión: 9.1 ULTRA-ENTERPRISE (Hardened & Bug-Fixed)
Estándares: ISA 240, INTOSAI ISSAI 5270, Ley 340-06, Ley 155-17, DGII 606/607
Autor: Pedro Baldera
================================================================================
"""

import os
import io
import re
import math
import json
import zipfile
import hashlib
import calendar
import datetime
import collections
import sqlite3
import logging
from flask import Flask, jsonify, render_template_string, send_file, request, session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

# Configuración de Logging Forense
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BASA_CORE")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "basa_sec_key_2026_forensic_big4_enterprise")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Seguridad de cabeceras HTTP y CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.after_request
def aplicar_cabeceras_seguridad(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ==============================================================================
# CONFIGURACIÓN FINANCIERA Y MÓDULOS
# ==============================================================================
BHD_CUENTA = os.environ.get("BHD_CUENTA", "08694150021")
TITULAR = os.environ.get("TITULAR_CUENTA", "Pedro Baldera")
CONTACTO = os.environ.get("CONTACTO_OFICIAL", "licpedrobaldera@gmail.com / +1 829 771 7390")
DB_PATH = os.environ.get("BASA_DB_PATH", "basa_audit_vault.db")

MODULOS_ENTERPRISE = {
    "B4_BASE": {"nombre": "B4 Base Core - Dictamen Pericial, Cadena SHA-256 & Matriz ISA 240", "precio": 12500, "incluido": True, "desc": "Núcleo obligatorio judicial"},
    "M1_BENFORD_SPECTRUM": {"nombre": "M1 - Motor Benford de 1er y 2do Dígito + Chi-Cuadrado", "precio": 5500, "incluido": False, "desc": "Detecta alteración contable humana en facturación masiva"},
    "M2_FRACCIONAMIENTO_340": {"nombre": "M2 - Algoritmo Anti-Fraccionamiento Ley 340-06 & Smurfing", "precio": 6000, "incluido": False, "desc": "Cálculo de clustering bajo umbrales de compra pública"},
    "M3_SHELL_COMPANIES": {"nombre": "M3 - Detector de Empresas Fantasma y Proveedores Espejo", "precio": 7000, "incluido": False, "desc": "Grafo de coincidencia de RNC, IP, cuentas y domicilios"},
    "M4_CONFLICTO_INTERES": {"nombre": "M4 - Matriz de Consanguinidad y Cruce de PEPs", "precio": 6500, "incluido": False, "desc": "Cruce contra nóminas públicas y padrón"},
    "M5_NOMINA_FANTASMA": {"nombre": "M5 - Auditoría Forense de Nómina y TSS Descuadrado", "precio": 5000, "incluido": False, "desc": "Detecta desvío hacia cuentas puente y sueldos dobles"},
    "M6_EVASION_DGII": {"nombre": "M6 - Detector de Evasión Fiscal y Descuadre Formatos 606/607", "precio": 8000, "incluido": False, "desc": "Inspección de NCF apócrifos y simulación de ITBIS"},
    "M7_DESVIO_FONDOS": {"nombre": "M7 - Triangulación de Fondos y Lavado Ley 155-17", "precio": 9000, "incluido": False, "desc": "Detección de pagos circulares y cuentas de paso"},
    "M8_FORENSIC_AI_REPORT": {"nombre": "M8 - Generador Automático de Querellas Judiciales", "precio": 8500, "incluido": False, "desc": "Redacción técnica pericial con marco procesal dominicano"}
}

# ==============================================================================
# PERSISTENCIA ROBUSTA (SQLITE SEGURO PARA DICTÁMENES Y CONTRATOS)
# ==============================================================================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contratos (
                contrato_id TEXT PRIMARY KEY,
                empresa TEXT,
                rnc TEXT,
                modulos TEXT,
                total_mensual REAL,
                primer_pago REAL,
                hash_seguridad TEXT,
                fecha TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dictamenes (
                dictamen_id TEXT PRIMARY KEY,
                fecha TEXT,
                score_riesgo REAL,
                payload_json TEXT,
                hash_sha256 TEXT
            )
        """)
        conn.commit()

init_db()

def safe_float(valor, default=0.0):
    """Convierte cadenas contables a float de forma segura."""
    if valor is None:
        return default
    if isinstance(valor, (int, float)):
        return float(valor)
    try:
        limpio = str(valor).replace(",", "").replace("$", "").replace("RD", "").strip()
        return float(limpio)
    except (ValueError, TypeError):
        return default

# ==============================================================================
# MOTOR FORENSE CUANTITATIVO (ALGORITMOS AUDITABLES)
# ==============================================================================
class ForensicAuditEngine:
    BENFORD_PROBABILITIES = {
        1: 0.30103, 2: 0.17609, 3: 0.12494, 4: 0.09691,
        5: 0.07918, 6: 0.06695, 7: 0.05799, 8: 0.05115, 9: 0.04576
    }

    @staticmethod
    def ejecutar_benford(transacciones):
        digitos = []
        for t in transacciones:
            monto = abs(safe_float(t.get("monto", 0)))
            if monto >= 1.0:
                # Extrae el primer dígito no cero de forma segura
                monto_str = re.sub(r"[^0-9]", "", f"{monto:.4f}").lstrip("0")
                if monto_str:
                    primer_digito = int(monto_str[0])
                    if 1 <= primer_digito <= 9:
                        digitos.append(primer_digito)

        n = len(digitos)
        if n < 20:
            return {"valido": False, "motivo": f"Muestra insuficiente ({n}/20 transacciones válidas)", "score_anomalia": 0}

        conteo = collections.Counter(digitos)
        chi_square = 0.0
        distribucion = {}

        for d in range(1, 10):
            esperado = n * ForensicAuditEngine.BENFORD_PROBABILITIES[d]
            observado = conteo.get(d, 0)
            chi_square += ((observado - esperado) ** 2) / esperado
            distribucion[d] = {
                "observado": observado,
                "pct_observado": round((observado / n) * 100, 2),
                "pct_esperado": round(ForensicAuditEngine.BENFORD_PROBABILITIES[d] * 100, 2)
            }

        # Grados de libertad = 8. Valor crítico Chi-sq a 99% confianza = 20.09
        manipulacion_detectada = chi_square > 20.09
        score = min(100.0, round((chi_square / 40.0) * 100, 2))

        return {
            "valido": True,
            "total_transacciones": n,
            "chi_cuadrado": round(chi_square, 4),
            "valor_critico_99": 20.09,
            "alteracion_sintetica_detectada": manipulacion_detectada,
            "score_anomalia": score,
            "distribucion": distribucion
        }

    @staticmethod
    def detector_fraccionamiento(transacciones, umbral_limite=180000.0, ventana_dias=15):
        hallazgos = []
        proveedores = collections.defaultdict(list)

        for t in transacciones:
            rnc = str(t.get("rnc_proveedor") or t.get("beneficiario") or "DESCONOCIDO").strip()
            proveedores[rnc].append(t)

        for rnc, items in proveedores.items():
            if len(items) < 2 or rnc == "DESCONOCIDO":
                continue

            # Orden cronológico seguro
            def parse_fecha(item):
                f_str = item.get("fecha")
                if not f_str:
                    return datetime.datetime.min
                for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d"):
                    try:
                        return datetime.datetime.strptime(str(f_str).strip(), fmt)
                    except ValueError:
                        pass
                return datetime.datetime.min

            items_ordenados = sorted(items, key=parse_fecha)
            clusters_detectados = []

            for i in range(len(items_ordenados)):
                f_base = parse_fecha(items_ordenados[i])
                if f_base == datetime.datetime.min:
                    continue

                cluster_actual = [items_ordenados[i]]
                for j in range(i + 1, len(items_ordenados)):
                    f_comp = parse_fecha(items_ordenados[j])
                    if f_comp == datetime.datetime.min:
                        continue
                    if 0 <= (f_comp - f_base).days <= ventana_dias:
                        cluster_actual.append(items_ordenados[j])

                if len(cluster_actual) >= 2:
                    suma = sum(safe_float(x.get("monto", 0)) for x in cluster_actual)
                    individuales_bajo_tope = all(safe_float(x.get("monto", 0)) < umbral_limite for x in cluster_actual)
                    
                    if individuales_bajo_tope and suma >= umbral_limite:
                        ids_cluster = sorted([str(x.get("id") or x.get("ncf")) for x in cluster_actual])
                        # Evitar reportar duplicados idénticos en la ventana
                        if ids_cluster not in clusters_detectados:
                            clusters_detectados.append(ids_cluster)
                            hallazgos.append({
                                "proveedor": rnc,
                                "tipo_violacion": "Fraccionamiento de Compras (Ley 340-06 Art. 14 / Art. 65)",
                                "total_fraccionado": round(suma, 2),
                                "umbral_violado": umbral_limite,
                                "cantidad_facturas": len(cluster_actual),
                                "evidencias": ids_cluster,
                                "riesgo": "CRÍTICO (Dolo e intento deliberado de evadir licitación pública)"
                            })

        return hallazgos

    @staticmethod
    def detector_red_empresas_espejo(proveedores):
        anomalias = []
        direcciones = collections.defaultdict(set)
        cuentas = collections.defaultdict(set)
        telefonos = collections.defaultdict(set)

        for p in proveedores:
            rnc = str(p.get("rnc") or "").strip()
            if not rnc:
                continue

            dir_val = str(p.get("direccion") or "").strip().lower()
            cta_val = str(p.get("cuenta_bancaria") or "").strip()
            tel_val = str(p.get("telefono") or "").strip()

            if len(dir_val) > 5:
                direcciones[dir_val].add(rnc)
            if len(cta_val) > 4:
                cuentas[cta_val].add(rnc)
            if len(tel_val) > 6:
                telefonos[tel_val].add(rnc)

        for d, lista in direcciones.items():
            if len(lista) > 1:
                anomalias.append({
                    "patron": "Domicilio fiscal idéntico compartido entre empresas supuestamente competidoras",
                    "coincidencia": d,
                    "empresas_involucradas": list(lista),
                    "violacion": "Colusión en licitación pública y creación de empresas pantalla (Ley 340-06)"
                })

        for c, lista in cuentas.items():
            if len(lista) > 1:
                anomalias.append({
                    "patron": "Misma cuenta bancaria de cobro receptora para múltiples RNC/Proveedores",
                    "coincidencia": c,
                    "empresas_involucradas": list(lista),
                    "violacion": "Concentración e intermediación financiera sospechosa (Ley 155-17 Lavado de Activos)"
                })

        return anomalias

    @staticmethod
    def detector_inconsistencias_fiscales(facturas_606, reporte_607):
        inconsistencias = []
        facturas_ventas = {str(f.get("ncf")).strip(): f for f in reporte_607 if f.get("ncf")}

        for f in facturas_606:
            ncf = str(f.get("ncf") or "").strip()
            monto_compra = safe_float(f.get("monto_facturado", 0))

            if ncf and (ncf.startswith("B01") or ncf.startswith("E31")):
                if facturas_ventas and ncf not in facturas_ventas:
                    inconsistencias.append({
                        "ncf": ncf,
                        "proveedor_rnc": f.get("rnc"),
                        "monto": monto_compra,
                        "tipo": "NCF no reportado por el emisor en Declaración Formato 607",
                        "riesgo_fiscal": "Defraudación Tributaria y Facturación Apócrifa (Ley 11-92 Art. 236)"
                    })

            # Montos cerrados atípicos en operaciones significativas
            if monto_compra >= 100000 and int(monto_compra) % 10000 == 0:
                inconsistencias.append({
                    "ncf": ncf or "SIN_NCF",
                    "monto": monto_compra,
                    "tipo": "Facturación con monto redondo cerrado atípico",
                    "riesgo_fiscal": "Posible pago de gratificación o soborno simulado"
                })

        return inconsistencias


# ==============================================================================
# MOTOR DE CONTRATOS Y FACTURACIÓN
# ==============================================================================
def calcular_facturacion(modulos_activos):
    hoy = datetime.date.today()
    _, dias_mes = calendar.monthrange(hoy.year, hoy.month)
    dias_restantes = max(1, dias_mes - hoy.day + 1)
    
    # Asegurar B4_BASE inmutablemente
    modulos_set = set(modulos_activos or [])
    modulos_set.add("B4_BASE")
    modulos_finales = sorted(list(modulos_set))

    total_mensual = sum(MODULOS_ENTERPRISE[m]["precio"] for m in modulos_finales if m in MODULOS_ENTERPRISE)
    primer_pago_prorrateado = round((total_mensual / dias_mes) * dias_restantes, 2)
    proximo_pago = (hoy + datetime.timedelta(days=dias_restantes)).strftime("%d/%m/%Y")
    ahorro_anual = round(total_mensual * 12 * 0.20, 2)

    return {
        "modulos": modulos_finales,
        "total_mensual": total_mensual,
        "primer_pago_prorrateado": primer_pago_prorrateado,
        "dias_restantes_mes": dias_restantes,
        "proximo_pago": proximo_pago,
        "ahorro_anual": ahorro_anual
    }


# ==============================================================================
# RUTAS DE INTERFAZ Y DASHBOARD
# ==============================================================================
@app.route('/')
def home():
    return render_template_string("""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BASA V9.1 - Forensic Intelligence Core</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
    <style>
        :root { --bg-primary: #070b13; --bg-secondary: #0d1525; --card-bg: #141f36; --accent-green: #00f090; --accent-cyan: #00d8f6; --text-main: #f0f4f8; --text-muted: #8a99ad; --border: #223455; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: var(--bg-primary); color: var(--text-main); font-family: 'Inter', sans-serif; padding: 25px; line-height: 1.6; }
        .header { max-width: 1280px; margin: 0 auto 25px auto; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 15px; }
        .logo { font-family: 'JetBrains Mono', monospace; font-size: 22px; font-weight: 800; color: var(--accent-green); }
        .container { max-width: 1280px; margin: auto; display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        @media (max-width: 900px) { .container { grid-template-columns: 1fr; } }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 22px; }
        .btn { display: inline-block; background: var(--accent-green); color: #05140d; font-weight: 700; padding: 12px 18px; border-radius: 8px; border: none; cursor: pointer; font-family: 'JetBrains Mono', monospace; font-size: 13px; text-decoration: none; }
        .btn:hover { background: #22ffa0; }
        .code-box { background: #06090f; border: 1px solid #1a273f; border-radius: 8px; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #b8c8dd; overflow-x: auto; max-height: 280px; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo">⚡ BASA V9.1 FORENSIC ENTERPRISE</div>
            <div style="font-size: 12px; color: var(--text-muted);">Auditoría Cuantitativa ISA 240, Ley 340-06 & Prevención Lavado Ley 155-17</div>
        </div>
        <div style="font-family: monospace; font-size: 12px; color: var(--accent-cyan); border: 1px solid #223455; padding: 6px 12px; border-radius: 6px;">SISTEMA ACTIVO</div>
    </div>
    <div class="container">
        <div>
            <div class="card" style="margin-bottom: 20px;">
                <h2>🚀 Consola de Peritaje Contable y Forense</h2>
                <p style="color: var(--text-muted); margin: 10px 0 18px 0; font-size: 14px;">
                    Inspección de anomalías probabilísticas (Benford), fraccionamiento doloso en compras estatales y comprobación cruzada de NCFs fiscales.
                </p>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="btn" onclick="ejecutarDemo()">⚡ EJECUTAR AUDITORÍA PERICIAL</button>
                    <a href="/activar-modulos" class="btn" style="background:var(--accent-cyan); color:#04141a;">⚙️ CONFIGURAR LICENCIA</a>
                    <a href="/b4/descargar/todo" class="btn" style="background:#223455; color:white;">📦 DESCARGAR EXPEDIENTE COMPLETO</a>
                </div>
            </div>
            <div class="card">
                <h3>🔍 Monitor de Resultados de la Inspección</h3>
                <div id="status" style="font-size: 13px; margin: 8px 0; color: #ffaa00;">Listo para procesar transacciones.</div>
                <div class="code-box" id="output">[STANDBY] Esperando orden de ejecución pericial...</div>
            </div>
        </div>
        <div>
            <div class="card">
                <h3>💳 Cuentas Corporativas</h3>
                <div style="background: #080d18; border: 1px solid #223455; padding: 12px; border-radius: 8px; margin: 15px 0;">
                    <div style="font-size: 11px; color: var(--text-muted);">BANCO BHD REPÚBLICA DOMINICANA</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 17px; color: var(--accent-green); font-weight: bold;">
                        """ + BHD_CUENTA + """
                    </div>
                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 5px;">Titular: """ + TITULAR + """</div>
                    <div style="font-size: 11px; color: var(--accent-cyan); margin-top: 3px;">""" + CONTACTO + """</div>
                </div>
                <a href="/api/contrato/preview" class="btn" style="width: 100%; text-align: center; background:#1b2d4b; color:white;">VER MODELO DE CONTRATO</a>
            </div>
        </div>
    </div>
    <script>
        function ejecutarDemo() {
            const out = document.getElementById("output");
            const st = document.getElementById("status");
            st.innerHTML = "⏳ Ejecutando análisis cuantitativo de evidencias...";
            out.innerHTML = "[PROCESANDO] Evaluando Benford, Fraccionamiento y NCFs...";

            fetch('/api/v8/forensic-inspect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            })
            .then(res => res.json())
            .then(data => {
                st.innerHTML = "✅ Inspección finalizada. Riesgo: " + data.nivel_riesgo_global;
                out.innerHTML = JSON.stringify(data, null, 2);
            })
            .catch(err => {
                st.innerHTML = "❌ Error en análisis";
                out.innerHTML = "Error: " + err;
            });
        }
    </script>
</body>
</html>
""")

@app.route('/activar-modulos')
def activar_modulos():
    fact = calcular_facturacion(["B4_BASE"])
    mods_html = ""
    for key, m in MODULOS_ENTERPRISE.items():
        checked = "checked" if m.get("incluido") else ""
        disabled = "disabled" if m.get("incluido") else ""
        mods_html += f"""
        <div style='background:#101a2d; border:1px solid #223455; border-radius:8px; padding:12px; margin-bottom:10px; display:flex; justify-content:space-between; align-items:center;'>
            <div>
                <b style='color:#00f090; font-size:14px;'>{m['nombre']}</b><br>
                <span style='color:#8a99ad; font-size:12px;'>{m.get('desc')}</span><br>
                <span style='font-family:monospace; color:#00d8f6; font-size:13px;'>RD$ {m['precio']:,} / mes</span>
            </div>
            <div>
                <input type='checkbox' {checked} {disabled} value='{key}' onchange='recalcular()' class='chk-mod' style='width:22px; height:22px; cursor:pointer;'>
            </div>
        </div>
        """

    return render_template_string(f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Suscripción de Módulos - BASA V9.1</title>
    <style>
        body {{ background: #070b13; color: #f0f4f8; font-family: sans-serif; padding: 25px; }}
        .card {{ background: #0d1525; border: 1px solid #223455; max-width: 900px; margin: auto; padding: 25px; border-radius: 12px; }}
        .btn {{ padding: 12px 20px; border-radius: 8px; border: none; font-weight: bold; cursor: pointer; text-decoration: none; }}
        .btn-green {{ background: #00f090; color: #05140d; width: 100%; font-size: 15px; margin-top: 15px; }}
        .input-box {{ width: 100%; padding: 10px; background: #080d18; border: 1px solid #223455; border-radius: 6px; color: white; margin: 6px 0 12px 0; }}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="color:#00f090; margin-bottom: 10px;">⚙️ Licenciamiento Modular BASA Forensics</h2>
        <p style="color:#8a99ad; margin-bottom: 20px; font-size: 14px;">Active los módulos requeridos para su dictamen pericial:</p>
        
        {mods_html}

        <div style="background:#14223d; border:1px solid #2a416d; padding:18px; border-radius:8px; margin-top:15px;">
            <h3 style="color:#00d8f6; margin-bottom: 10px;">Datos de Facturación</h3>
            <label style="font-size: 13px;">Firma / Cliente:</label>
            <input type="text" id="empresa" class="input-box" placeholder="Ej: Auditoría Forense Dominicana SRL">
            <label style="font-size: 13px;">RNC:</label>
            <input type="text" id="rnc" class="input-box" placeholder="Ej: 131-00000-0">
            <div id="fact-box" style="font-family: monospace; font-size: 13px; color: #d0e2ff; margin-top: 10px;">Calculando...</div>
        </div>

        <button class="btn btn-green" onclick="activarLicencia()">✅ EMITIR ORDEN Y REGISTRAR LICENCIA</button>
        <div id="resultado" style="display:none; margin-top:15px; background:#0e291e; border:1px solid #00f090; padding:15px; border-radius:8px; font-family: monospace; font-size: 13px;"></div>
    </div>

    <script>
        let modulos = ['B4_BASE'];

        function recalcular() {{
            modulos = ['B4_BASE'];
            document.querySelectorAll('.chk-mod:checked').forEach(c => {{
                if(c.value !== 'B4_BASE') modulos.push(c.value);
            }});

            fetch('/api/facturacion', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ modulos: modulos }})
            }})
            .then(r => r.json())
            .then(d => {{
                document.getElementById('fact-box').innerHTML = `
                    Módulos: ${{d.modulos.length}} | Mensualidad: RD$ ${{d.total_mensual.toLocaleString()}}<br>
                    <b>Primer Cobro Prorrateado (${{d.dias_restantes_mes}} días):</b> <span style="color:#00f090;">RD$ ${{d.primer_pago_prorrateado.toLocaleString()}}</span><br>
                    Cuenta: BHD {BHD_CUENTA} ({TITULAR})
                `;
            }});
        }}

        function activarLicencia() {{
            const emp = document.getElementById('empresa').value || 'Auditor Independiente';
            const rnc = document.getElementById('rnc').value || '000000000';

            fetch('/api/activar', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ modulos: modulos, empresa: emp, rnc: rnc }})
            }})
            .then(r => r.json())
            .then(d => {{
                const res = document.getElementById('resultado');
                res.style.display = 'block';
                res.innerHTML = `
                    <b>Contrato Registrado:</b> ${{d.contrato_id}}<br>
                    <b>Monto a Transferir:</b> RD$ ${{d.facturacion.primer_pago_prorrateado.toLocaleString()}}<br>
                    <b>Hash Criptográfico:</b> ${{d.hash_seguridad}}<br><br>
                    <a href="/api/contrato/descargar/${{d.contrato_id}}" class="btn" style="background:#00d8f6; color:black; padding:8px 14px;">Descargar Copia Certificada</a>
                `;
            }});
        }}
        recalcular();
    </script>
</body>
</html>
""")


# ==============================================================================
# ENDPOINTS API (ACEPTA DATOS REALES O CARGA DEMO EN SU DEFECTO)
# ==============================================================================
@app.route('/api/v8/forensic-inspect', methods=['POST'])
def api_forensic_inspect():
    data = request.get_json(silent=True) or {}

    # Si el usuario envía sus transacciones las procesa; de lo contrario usa el demo pericial
    transacciones = data.get("transacciones")
    if not transacciones or not isinstance(transacciones, list):
        transacciones = [
            {"id": "TRX-101", "fecha": "2026-03-01", "monto": 178500.0, "rnc_proveedor": "130-99881-2", "ncf": "E3100000001"},
            {"id": "TRX-102", "fecha": "2026-03-03", "monto": 179200.0, "rnc_proveedor": "130-99881-2", "ncf": "E3100000002"},
            {"id": "TRX-103", "fecha": "2026-03-05", "monto": 175000.0, "rnc_proveedor": "130-99881-2", "ncf": "E3100000003"},
            {"id": "TRX-104", "fecha": "2026-03-10", "monto": 2500000.0, "rnc_proveedor": "131-00122-3", "ncf": "B0100000099"},
            {"id": "TRX-105", "fecha": "2026-03-12", "monto": 300000.0, "rnc_proveedor": "131-44551-9", "ncf": "B0100000100"}
        ]
        # Transacciones sintéticas para calibrar Benford
        for idx, m in enumerate([11200, 14500, 18900, 19200, 21000, 28000, 31000, 42000, 51000, 68000, 79000, 89000, 95000] * 3):
            transacciones.append({
                "id": f"TRX-SYNTH-{idx}",
                "fecha": "2026-03-16",
                "monto": m,
                "rnc_proveedor": "132-77112-9",
                "ncf": f"B01000002{idx}"
            })

    proveedores = data.get("proveedores")
    if not proveedores or not isinstance(proveedores, list):
        proveedores = [
            {"rnc": "130-99881-2", "nombre": "Constructora Alpha SRL", "direccion": "Av. 27 de Febrero #200, DN", "cuenta_bancaria": "9901-8821"},
            {"rnc": "131-44551-9", "nombre": "Servicios Globales Beta SRL", "direccion": "Av. 27 de Febrero #200, DN", "cuenta_bancaria": "9901-8821"},
            {"rnc": "131-00122-3", "nombre": "Asesorías Delta SRL", "direccion": "Calle Sol #12, Santiago", "cuenta_bancaria": "1123-0091"}
        ]

    facturas_606 = data.get("facturas_606")
    if not facturas_606 or not isinstance(facturas_606, list):
        facturas_606 = [
            {"ncf": "B0100000099", "rnc": "131-00122-3", "monto_facturado": 2500000.0},
            {"ncf": "B0199999999", "rnc": "139-99999-9", "monto_facturado": 4500000.0}
        ]

    reporte_607 = data.get("reporte_607")
    if not reporte_607 or not isinstance(reporte_607, list):
        reporte_607 = [{"ncf": "B0100000099", "monto": 2500000.0}]

    umbral_limite = safe_float(data.get("umbral_compras"), 180000.0)

    # Ejecución de Módulos
    res_benford = ForensicAuditEngine.ejecutar_benford(transacciones)
    res_fraccionamiento = ForensicAuditEngine.detector_fraccionamiento(transacciones, umbral_limite=umbral_limite)
    res_espejo = ForensicAuditEngine.detector_red_empresas_espejo(proveedores)
    res_fiscal = ForensicAuditEngine.detector_inconsistencias_fiscales(facturas_606, reporte_607)

    score_total = (
        (50 if res_fraccionamiento else 0) +
        (35 if res_espejo else 0) +
        (25 if res_fiscal else 0) +
        (res_benford.get("score_anomalia", 0) * 0.3)
    )
    score_total = min(100.0, round(score_total, 1))

    dictamen_id = f"DICTAMEN-B4-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    fecha_emision = datetime.datetime.now().isoformat()
    evidencia_hash = hashlib.sha256(json.dumps(transacciones, sort_keys=True).encode()).hexdigest()

    reporte = {
        "dictamen_pericial_id": dictamen_id,
        "fecha_emision": fecha_emision,
        "nivel_riesgo_global": "CRÍTICO / INDICIOS PENALES" if score_total > 50 else "BAJO / CONFORME",
        "fraud_risk_score": score_total,
        "modulos_evaluados": {
            "M1_benford": res_benford,
            "M2_fraccionamiento_ley_340": res_fraccionamiento,
            "M3_empresas_espejo_colusion": res_espejo,
            "M6_evasion_dgii_ncf": res_fiscal
        },
        "evidencia_criptografica_sha256": evidencia_hash,
        "recomendacion_procesal": (
            "Apoderar de inmediato a la Dirección General de Contrataciones Públicas (DGCP), "
            "Cámara de Cuentas de la República Dominicana o PEPCA según corresponda por las violaciones detectadas."
        )
    }

    # Persistencia en BD local
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO dictamenes (dictamen_id, fecha, score_riesgo, payload_json, hash_sha256)
            VALUES (?, ?, ?, ?, ?)
        """, (dictamen_id, fecha_emision, score_total, json.dumps(reporte), evidencia_hash))
        conn.commit()

    return jsonify(reporte)


@app.route('/api/facturacion', methods=['POST'])
def api_facturacion():
    data = request.get_json(silent=True) or {}
    mods = data.get('modulos', ["B4_BASE"])
    res = calcular_facturacion(mods)
    res["bhd"] = BHD_CUENTA
    res["titular"] = TITULAR
    return jsonify(res)


@app.route('/api/activar', methods=['POST'])
def api_activar():
    data = request.get_json(silent=True) or {}
    contrato_id = f"CTR-B4-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    modulos = data.get('modulos', ["B4_BASE"])
    fact = calcular_facturacion(modulos)

    empresa = str(data.get('empresa', 'Firma Auditora')).strip()
    rnc = str(data.get('rnc', '000000000')).strip()

    contrato_payload = f"{contrato_id}|{empresa}|{rnc}|{fact['total_mensual']}"
    hash_seguridad = hashlib.sha256(contrato_payload.encode()).hexdigest()
    fecha_iso = datetime.datetime.now().isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO contratos (contrato_id, empresa, rnc, modulos, total_mensual, primer_pago, hash_seguridad, fecha)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (contrato_id, empresa, rnc, ",".join(fact["modulos"]), fact["total_mensual"], fact["primer_pago_prorrateado"], hash_seguridad, fecha_iso))
        conn.commit()

    return jsonify({
        "contrato_id": contrato_id,
        "facturacion": fact,
        "hash_seguridad": hash_seguridad,
        "bhd": BHD_CUENTA,
        "titular": TITULAR
    })


@app.route('/api/contrato/preview')
def contrato_preview():
    doc = f"""================================================================================
CONTRATO VIRTUAL DE LICENCIAMIENTO DE SOFTWARE FORENSE BIG FOUR - BASA V9.1
================================================================================
FECHA DE EMISIÓN: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
PROVEEDOR: BASA FORENSIC INTELLIGENCE (Titular: {TITULAR})
CUENTA BHD DESIGNADA: {BHD_CUENTA}
CONTACTO: {CONTACTO}

CLÁUSULA 1: OBJETO
Licenciamiento de capacidades analíticas automatizadas bajo estándares ISA 240, 
INTOSAI ISSAI 5270, Ley 340-06 de Contrataciones Públicas y Ley 155-17 contra Lavado.
================================================================================
"""
    buf = io.BytesIO(doc.encode('utf-8'))
    return send_file(buf, mimetype="text/plain", as_attachment=True, download_name="CONTRATO_BASA_PREVIEW.txt")


@app.route('/api/contrato/descargar/<contrato_id>')
def contrato_descargar(contrato_id):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT empresa, rnc, modulos, total_mensual, primer_pago, hash_seguridad, fecha FROM contratos WHERE contrato_id = ?", (contrato_id,))
        row = cursor.fetchone()

    if not row:
        return jsonify({"error": "Contrato no localizado en la bóveda de auditoría"}), 404

    empresa, rnc, modulos, total_m, primer_pago, hash_s, fecha = row

    doc = f"""================================================================================
CONTRATO PERICIAL DE LICENCIA SELLADO DIGITALMENTE
IDENTIFICADOR ÚNICO: {contrato_id}
HASH SHA-256: {hash_s}
FECHA REGISTRO: {fecha}
================================================================================
CLIENTE / FIRMA AUDITORA: {empresa}
RNC REGISTRADO: {rnc}
MÓDULOS ACTIVOS: {modulos}
MENSUALIDAD ACORDADA: RD$ {total_m:,.2f}
MONTO PRIMER PAGO: RD$ {primer_pago:,.2f}
CUENTA RECEPTORA BHD: {BHD_CUENTA} | TITULAR: {TITULAR}
"""
    buf = io.BytesIO(doc.encode('utf-8'))
    return send_file(buf, mimetype="text/plain", as_attachment=True, download_name=f"{contrato_id}_CERTIFICADO.txt")


@app.route('/b4/descargar/todo')
def b4_descargar_todo():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("01_DICTAMEN_PERICIAL_BASE.txt",
                    f"DICTAMEN PERICIAL EMITIDO BAJO ISA 240 / LEY 340-06\n"
                    f"Titular Certificado: {TITULAR} (BHD: {BHD_CUENTA})\n"
                    f"Generado: {datetime.datetime.now().isoformat()}\n")
        zf.writestr("02_MATRIZ_HALLAZGOS_LEY_340_06.csv",
                    "ID,PROVEEDOR,NCF,MONTO,TIPO_HALLAZGO,NORMA_VIOLADA\n"
                    "1,Constructora Alpha,E3100000001,178500,Fraccionamiento,Art 14 Ley 340-06\n"
                    "2,Constructora Alpha,E3100000002,179200,Fraccionamiento,Art 14 Ley 340-06\n")

    memory_file.seek(0)
    return send_file(memory_file, mimetype="application/zip", as_attachment=True, download_name="EXPEDIENTE_FORENSE.zip")


@app.route('/healthz')
def healthz():
    return jsonify({
        "status": "OPERATIONAL",
        "engine": "BASA V9.1 ENTERPRISE",
        "bhd_cuenta": BHD_CUENTA,
        "titular": TITULAR,
        "timestamp": datetime.datetime.now().isoformat()
    })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
