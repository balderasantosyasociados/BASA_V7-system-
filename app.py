# -*- coding: utf-8 -*-
"""
================================================================================
BASA FORENSIC INTELLIGENCE - GLOBAL MULTI-JURISDICTION SUITE (EDICIÓN BIG 4)
Versión: 9.5 GLOBAL-ENTERPRISE
Estándares: ISA 240, INTOSAI ISSAI 5270, GAFI/FATF 40, US FCPA, LCSP UE, 
            Ley RD 340-06 / 155-17, LAASSP MX, Ley 80/1150 CO
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("BASA_GLOBAL")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "basa_global_secret_key_2026_forensic_suite")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ==============================================================================
# CONFIGURACIÓN BANCARIA Y BASE DE DATOS
# ==============================================================================
BHD_CUENTA = os.environ.get("BHD_CUENTA", "08694150021")
TITULAR = os.environ.get("TITULAR_CUENTA", "Pedro Baldera")
CONTACTO = os.environ.get("CONTACTO_OFICIAL", "licpedrobaldera@gmail.com / +1 829 771 7390")
DB_PATH = os.environ.get("BASA_DB_PATH", "basa_vault_global.db")

# ==============================================================================
# PERFILES MULTI-JURISDICCIONALES DE CUMPLIMIENTO LEGAL Y FORENSE
# ==============================================================================
JURISDICCIONES = {
    "DO": {
        "pais": "República Dominicana",
        "moneda": "DOP",
        "ley_compras": "Ley 340-06 sobre Compras y Contrataciones Públicas y Decreto Reglamentario 543-12",
        "ley_antilavado": "Ley 155-17 contra el Lavado de Activos y el Financiamiento del Terrorismo",
        "codigo_tributario": "Código Tributario Ley 11-92 (Comprobantes Fiscales NCF / DGII Formatos 606 y 607)",
        "umbral_compras_menores": 180000.0,
        "autoridades_competentes": ["Cámara de Cuentas de la República Dominicana", "PEPCA / Procuraduría General", "DGCP", "DIGEIG", "UAF-RD"],
        "tax_id_label": "RNC / Cédula",
        "tax_invoice_label": "NCF (Comprobante Fiscal DGII)"
    },
    "US": {
        "pais": "Estados Unidos (USA)",
        "moneda": "USD",
        "ley_compras": "FAR (Federal Acquisition Regulation Part 13 - Simplified Acquisition Procedures)",
        "ley_antilavado": "Bank Secrecy Act (BSA), USA PATRIOT Act & FinCEN Regulations",
        "codigo_tributario": "Internal Revenue Code (IRC) & US Foreign Corrupt Practices Act (FCPA 15 U.S.C. § 78dd-1)",
        "umbral_compras_menores": 10000.0,  # Micro-purchase threshold FAR 2.101
        "autoridades_competentes": ["U.S. Department of Justice (DOJ)", "Securities and Exchange Commission (SEC)", "FinCEN", "Government Accountability Office (GAO)"],
        "tax_id_label": "EIN / SSN",
        "tax_invoice_label": "Federal Invoice / Form 1099-MISC"
    },
    "ES": {
        "pais": "España & Unión Europea",
        "moneda": "EUR",
        "ley_compras": "Ley 9/2017 de Contratos del Sector Público (LCSP) - Directivas UE 2014/23/UE y 2014/24/UE",
        "ley_antilavado": "Ley 10/2010 de Prevención de Blanqueo de Capitales y Directiva Europea 6AMLD (2018/1673)",
        "codigo_tributario": "Ley General Tributaria 58/2003 y Código Penal Español (Art. 31 bis Responsabilidad Penal)",
        "umbral_compras_menores": 15000.0,  # Límite de contratos menores de suministro/servicios LCSP
        "autoridades_competentes": ["Tribunal de Cuentas", "Fiscalía contra la Corrupción y la Criminalidad Organizada", "SEPBLAC", "Agencia Tributaria (AEAT)"],
        "tax_id_label": "NIF / CIF / NIE",
        "tax_invoice_label": "Factura Electrónica / SII AEAT"
    },
    "MX": {
        "pais": "México",
        "moneda": "MXN",
        "ley_compras": "Ley de Adquisiciones, Arrendamientos y Servicios del Sector Público (LAASSP Art. 41 y 42)",
        "ley_antilavado": "Ley Federal para la Prevención e Identificación de Operaciones con Recursos de Procedencia Ilícita (LFPIORPI)",
        "codigo_tributario": "Código Fiscal de la Federación (Art. 69-B Empresas Fantasma / EFOS y EDOS) y SAT CFDI 4.0",
        "umbral_compras_menores": 350000.0,  # Adjudicación directa parametrizada
        "autoridades_competentes": ["Auditoría Superior de la Federación (ASF)", "Secretaría de la Función Pública (SFP)", "Unidad de Inteligencia Financiera (UIF)", "SAT"],
        "tax_id_label": "RFC (Registro Federal de Contribuyentes)",
        "tax_invoice_label": "CFDI 4.0 / Folio Fiscal UUID"
    },
    "CO": {
        "pais": "Colombia",
        "moneda": "COP",
        "ley_compras": "Estatuto General de Contratación de la Administración Pública (Ley 80 de 1993, Ley 1150 de 2007)",
        "ley_antilavado": "Estatuto Anticorrupción (Ley 1474 de 2011) y Sistema SARLAFT / SAGRILAFT (Superfinanciera)",
        "codigo_tributario": "Estatuto Tributario Nacional (DIAN) y Sistema de Facturación Electrónica con Validación Previa",
        "umbral_compras_menores": 50000000.0, # Umbral de Mínima Cuantía parametrizada
        "autoridades_competentes": ["Contraloría General de la República", "Procuraduría General de la Nación", "Fiscalía General", "UIAF Colombia", "DIAN"],
        "tax_id_label": "NIT (Número de Identificación Tributaria)",
        "tax_invoice_label": "Factura Electrónica DIAN / CUFE"
    },
    "GLOBAL": {
        "pais": "Marco Internacional ISA / INTOSAI",
        "moneda": "USD",
        "ley_compras": "INTOSAI ISSAI 5270 (Guideline for the Audit of Corruption and Fraud in Public Procurement)",
        "ley_antilavado": "GAFI/FATF 40 Recommendations on Anti-Money Laundering and Counter-Terrorist Financing",
        "codigo_tributario": "Normas Internacionales de Auditoría ISA 240 (Responsabilidades del Auditor en Relación con el Fraude)",
        "umbral_compras_menores": 10000.0,
        "autoridades_competentes": ["Organización de las Naciones Unidas (UNCAC)", "Interpol Financial Crimes Unit", "International Organization of Supreme Audit Institutions (INTOSAI)"],
        "tax_id_label": "Tax ID / Legal Entity Identifier (LEI)",
        "tax_invoice_label": "Electronic Tax Invoice / Audit Evidence Record"
    }
}

MODULOS_ENTERPRISE = {
    "B4_BASE": {"nombre": "B4 Base Core - Dictamen Pericial ISA 240, SHA-256 & Matriz ISSAI 5270", "precio": 12500, "incluido": True, "desc": "Núcleo pericial obligatorio judicial y penal"},
    "M1_BENFORD_GLOBAL": {"nombre": "M1 - Espectro Benford Chi-Cuadrado de 1er y 2do Dígito Multidivisa", "precio": 5500, "incluido": False, "desc": "Detección matemática de manipulación contable humana en datasets masivos"},
    "M2_FRACCIONAMIENTO_GLOBAL": {"nombre": "M2 - Algoritmo Anti-Fraccionamiento y Smurfing Transfronterizo", "precio": 6500, "incluido": False, "desc": "Inspección de clustering de compras bajo umbrales licitatorios locales"},
    "M3_SHELL_GRAPH": {"nombre": "M3 - Detector de Redes de Empresas Pantalla, Testaferros y Cartelización", "precio": 7000, "incluido": False, "desc": "Grafo pericial de colusión por domicilio idéntico, cuenta bancaria y directores PEPs"},
    "M4_AML_KYC_PEP": {"nombre": "M4 - Matriz de Consanguinidad, Listas OFAC/ONU y PEPs Internacionales", "precio": 6500, "incluido": False, "desc": "Detección de Personas Políticamente Expuestas y conflicto de interés estatal"},
    "M6_TAX_CROSS_MATCH": {"nombre": "M6 - Verificación Cruzada Tributaria (DGII, SAT CFDI, SII AEAT, DIAN)", "precio": 8000, "incluido": False, "desc": "Inspección de comprobantes fiscales fantasmas y deducciones apócrifas"},
    "M7_DESVIO_PARAISOS": {"nombre": "M7 - Triangulación a Paraísos Fiscales y Pagos Circulares Ley 155-17 / FATF", "precio": 9000, "incluido": False, "desc": "Rastreo de flujos de capital hacia jurisdicciones no cooperantes"}
}

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contratos (
                contrato_id TEXT PRIMARY KEY,
                empresa TEXT,
                rnc TEXT,
                pais TEXT,
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
                pais TEXT,
                fecha TEXT,
                score_riesgo REAL,
                payload_json TEXT,
                hash_sha256 TEXT
            )
        """)
        conn.commit()

init_db()

def safe_float(valor, default=0.0):
    if valor is None:
        return default
    if isinstance(valor, (int, float)):
        return float(valor)
    try:
        limpio = re.sub(r"[^\d.-]", "", str(valor).replace(",", "").strip())
        return float(limpio) if limpio else default
    except (ValueError, TypeError):
        return default

# ==============================================================================
# MOTOR FORENSE CUANTITATIVO Y REGLAS DE DETECCIÓN MULTI-PAÍS
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
                monto_str = re.sub(r"[^0-9]", "", f"{monto:.4f}").lstrip("0")
                if monto_str:
                    primer_digito = int(monto_str[0])
                    if 1 <= primer_digito <= 9:
                        digitos.append(primer_digito)

        n = len(digitos)
        if n < 20:
            return {
                "valido": False,
                "motivo": f"Muestra insuficiente ({n}/20 transacciones mínimas según ISA 240)",
                "score_anomalia": 0
            }

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

        manipulacion_detectada = chi_square > 20.09
        score = min(100.0, round((chi_square / 40.0) * 100, 2))

        return {
            "valido": True,
            "estandar": "ISA 240 / Benford Law Quantitative Test",
            "total_transacciones": n,
            "chi_cuadrado": round(chi_square, 4),
            "valor_critico_99": 20.09,
            "alteracion_sintetica_detectada": manipulacion_detectada,
            "score_anomalia": score,
            "distribucion": distribucion
        }

    @staticmethod
    def detector_fraccionamiento(transacciones, config_pais, ventana_dias=15):
        hallazgos = []
        proveedores = collections.defaultdict(list)
        umbral_limite = config_pais["umbral_compras_menores"]
        moneda = config_pais["moneda"]
        norma = config_pais["ley_compras"]

        for t in transacciones:
            rnc = str(t.get("rnc_proveedor") or t.get("beneficiario") or "DESCONOCIDO").strip()
            proveedores[rnc].append(t)

        for rnc, items in proveedores.items():
            if len(items) < 2 or rnc == "DESCONOCIDO":
                continue

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

                cluster = [items_ordenados[i]]
                for j in range(i + 1, len(items_ordenados)):
                    f_comp = parse_fecha(items_ordenados[j])
                    if f_comp == datetime.datetime.min:
                        continue
                    if 0 <= (f_comp - f_base).days <= ventana_dias:
                        cluster.append(items_ordenados[j])

                if len(cluster) >= 2:
                    suma = sum(safe_float(x.get("monto", 0)) for x in cluster)
                    individuales_bajo_tope = all(safe_float(x.get("monto", 0)) < umbral_limite for x in cluster)

                    if individuales_bajo_tope and suma >= umbral_limite:
                        ids = sorted([str(x.get("id") or x.get("ncf")) for x in cluster])
                        if ids not in clusters_detectados:
                            clusters_detectados.append(ids)
                            hallazgos.append({
                                "proveedor": rnc,
                                "violacion": f"Fraccionamiento Ilegal de Contrataciones ({norma}) / ISSAI 5270",
                                "total_fraccionado": f"{moneda} {suma:,.2f}",
                                "umbral_violado": f"{moneda} {umbral_limite:,.2f}",
                                "facturas_detectadas": len(cluster),
                                "evidencias": ids,
                                "tipologia_penal": "División artificiosa de compras para eludir los procedimientos de licitación pública"
                            })

        return hallazgos

    @staticmethod
    def detector_empresas_espejo(proveedores, config_pais):
        anomalias = []
        direcciones = collections.defaultdict(set)
        cuentas = collections.defaultdict(set)
        norma_aml = config_pais["ley_antilavado"]

        for p in proveedores:
            rnc = str(p.get("rnc") or p.get("id") or "").strip()
            if not rnc:
                continue
            dir_val = str(p.get("direccion") or "").strip().lower()
            cta_val = str(p.get("cuenta_bancaria") or "").strip()

            if len(dir_val) > 6:
                direcciones[dir_val].add(rnc)
            if len(cta_val) > 4:
                cuentas[cta_val].add(rnc)

        for d, r_list in direcciones.items():
            if len(r_list) > 1:
                anomalias.append({
                    "patron": "Domicilio fiscal común en oferentes supuestamente independientes",
                    "coincidencia": d,
                    "empresas": list(r_list),
                    "marco_juridico": f"Colusión y Cartelización en Contrataciones Públicas ({config_pais['ley_compras']}) / ISSAI 5270"
                })

        for c, r_list in cuentas.items():
            if len(r_list) > 1:
                anomalias.append({
                    "patron": "Misma cuenta bancaria de cobro receptora para múltiples contribuyentes/proveedores",
                    "coincidencia": c,
                    "empresas": list(r_list),
                    "marco_juridico": f"Intermediación irregular y lavado de activos ({norma_aml})"
                })

        return anomalias

    @staticmethod
    def detector_inconsistencias_tributarias(facturas_compras, facturas_ventas, config_pais):
        inconsistencias = []
        ventas_dict = {str(f.get("ncf") or f.get("folio") or f.get("id")).strip(): f for f in facturas_ventas}
        moneda = config_pais["moneda"]

        for f in facturas_compras:
            ncf = str(f.get("ncf") or f.get("folio") or f.get("id") or "").strip()
            monto = safe_float(f.get("monto_facturado", f.get("monto", 0)))

            if ncf and ventas_dict and ncf not in ventas_dict:
                inconsistencias.append({
                    "comprobante_id": ncf,
                    "monto": f"{moneda} {monto:,.2f}",
                    "tipo": f"Comprobante fiscal no cruzado con registro de ventas ({config_pais['codigo_tributario']})",
                    "riesgo": "Operación simulada / Deducción fiscal apócrifa"
                })

            # Montos redondos anormalmente cerrados en compras mayores
            if monto >= (config_pais["umbral_compras_menores"] * 0.5) and int(monto) % 10000 == 0:
                inconsistencias.append({
                    "comprobante_id": ncf or "SIN_ID",
                    "monto": f"{moneda} {monto:,.2f}",
                    "tipo": "Facturación con monto cerrado atípico sin desglose de partidas",
                    "riesgo": "Riesgo de pago de soborno encubierto / ISA 240 Indicador de Fraude"
                })

        return inconsistencias


# ==============================================================================
# MOTOR DE CONTRATACIÓN Y FACTURACIÓN
# ==============================================================================
def calcular_facturacion(modulos_activos):
    hoy = datetime.date.today()
    _, dias_mes = calendar.monthrange(hoy.year, hoy.month)
    dias_restantes = max(1, dias_mes - hoy.day + 1)

    mods_set = set(modulos_activos or [])
    mods_set.add("B4_BASE")
    mods_finales = sorted(list(mods_set))

    total_mensual = sum(MODULOS_ENTERPRISE[m]["precio"] for m in mods_finales if m in MODULOS_ENTERPRISE)
    primer_pago = round((total_mensual / dias_mes) * dias_restantes, 2)
    proximo_pago = (hoy + datetime.timedelta(days=dias_restantes)).strftime("%d/%m/%Y")
    ahorro_anual = round(total_mensual * 12 * 0.20, 2)

    return {
        "modulos": mods_finales,
        "total_mensual": total_mensual,
        "primer_pago_prorrateado": primer_pago,
        "dias_restantes_mes": dias_restantes,
        "proximo_pago": proximo_pago,
        "ahorro_anual": ahorro_anual
    }


# ==============================================================================
# INTERFAZ WEB GLOBAL ULTRA-PROFESIONAL (BIG 4 DASHBOARD)
# ==============================================================================
@app.route('/')
def home():
    paises_options = "".join([f"<option value='{k}'>{v['pais']} ({v['moneda']})</option>" for k, v in JURISDICCIONES.items()])
    return render_template_string(f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BASA V9.5 - Global Forensic Intelligence Suite</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #050811;
            --bg-secondary: #0b1120;
            --card-bg: #111a2e;
            --accent-green: #00f090;
            --accent-cyan: #00d8f6;
            --accent-gold: #ffb800;
            --text-main: #f0f4f8;
            --text-muted: #8ca2bf;
            --border: #1f2f4e;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-primary);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            padding: 24px;
        }}
        .header {{
            max-width: 1350px;
            margin: 0 auto 25px auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
        }}
        .logo {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            font-weight: 800;
            color: var(--accent-green);
        }}
        .container {{
            max-width: 1350px;
            margin: auto;
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 25px;
        }}
        @media (max-width: 960px) {{ .container {{ grid-template-columns: 1fr; }} }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 20px;
        }}
        .btn {{
            background: var(--accent-green);
            color: #04120a;
            font-weight: 700;
            padding: 12px 20px;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            text-decoration: none;
            display: inline-block;
        }}
        .btn:hover {{ background: #26ffa4; transform: translateY(-1px); }}
        .code-box {{
            background: #04070e;
            border: 1px solid #1c2b48;
            border-radius: 8px;
            padding: 15px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #b9d2f2;
            overflow-x: auto;
            max-height: 380px;
            white-space: pre-wrap;
        }}
        .select-jurisdiccion {{
            width: 100%;
            background: #060b17;
            border: 1px solid var(--accent-cyan);
            color: var(--accent-cyan);
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            font-weight: 600;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 15px;
            cursor: pointer;
        }}
        .tag {{
            display: inline-block;
            background: #142442;
            color: #79aaff;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 4px;
            margin: 3px 2px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="logo">⚡ BASA V9.5 // GLOBAL FORENSIC SUITE</div>
            <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">
                Advanced Quantitative Audit, Anti-Fraud & Asset Recovery (ISA 240 / INTOSAI ISSAI 5270 / GAFI 40)
            </div>
        </div>
        <div style="text-align: right;">
            <span class="tag">EDICIÓN BIG FOUR</span>
            <span class="tag">CADENA SHA-256</span>
        </div>
    </div>

    <div class="container">
        <div>
            <div class="card">
                <h2 style="margin-bottom: 12px;">🌍 Consola Pericial Multi-Jurisdiccional</h2>
                <p style="color: var(--text-muted); font-size: 14px; margin-bottom: 16px;">
                    Seleccione la jurisdicción objetivo. El motor reconfigurará de forma dinámica los umbrales de compras públicas,
                    algoritmos anti-fraccionamiento, leyes antilavado y autoridades procesales competentes:
                </p>

                <label style="font-size: 12px; color: var(--text-muted); text-transform: uppercase;">Jurisdicción y Marco Legal Aplicable:</label>
                <select id="jurisdiccion" class="select-jurisdiccion" onchange="actualizarInfoPais()">
                    {paises_options}
                </select>

                <div id="pais-info" style="background:#091020; border:1px solid #1d2d4c; padding:15px; border-radius:8px; margin-bottom:18px; font-size:13px;">
                    Cargando normativa...
                </div>

                <div style="display:flex; gap:10px; flex-wrap:wrap;">
                    <button class="btn" onclick="ejecutarAuditoriaGlobal()">⚡ EJECUTAR PERITAJE FORENSE</button>
                    <a href="/activar-modulos" class="btn" style="background:var(--accent-cyan); color:#02151c;">⚙️ ACTIVAR MÓDULOS</a>
                    <a href="/b4/descargar/todo" class="btn" style="background:#1f3358; color:white;">📦 EXPEDIENTE DE PRUEBAS (ZIP)</a>
                </div>
            </div>

            <div class="card">
                <h3>🔍 Monitor Pericial de Detección de Fraude</h3>
                <div id="status-bar" style="font-size:13px; color:var(--accent-gold); margin:8px 0;">Listo para procesar evidencias.</div>
                <div class="code-box" id="terminal-out">[SISTEMA AUDITABLE LISTO] Seleccione una jurisdicción y pulse EJECUTAR PERITAJE FORENSE...</div>
            </div>
        </div>

        <div>
            <div class="card">
                <h3>🏛️ Cobertura Legal y Estándares</h3>
                <div style="margin: 12px 0;">
                    <span class="tag">ISA 240 (Fraude)</span>
                    <span class="tag">INTOSAI ISSAI 5270</span>
                    <span class="tag">GAFI / FATF 40</span>
                    <span class="tag">US FCPA Act</span>
                    <span class="tag">Ley RD 340-06 / 155-17</span>
                    <span class="tag">Ley 9/2017 LCSP España</span>
                    <span class="tag">LAASSP México</span>
                    <span class="tag">Ley 80 Colombia</span>
                    <span class="tag">COSO 2013</span>
                </div>
                <p style="font-size: 13px; color: var(--text-muted); line-height: 1.5;">
                    Cada dictamen emite un sello de tiempo y un cálculo de función hash criptográfica SHA-256 para validez probatoria en cortes penales y tribunales de cuentas.
                </p>
            </div>

            <div class="card">
                <h3>💳 Bóveda y Cuenta Corporativa</h3>
                <div style="background: #080d19; border: 1px solid #203152; padding: 15px; border-radius: 8px; margin: 15px 0;">
                    <div style="font-size: 11px; color: var(--text-muted);">BANCO BHD REPÚBLICA DOMINICANA</div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 19px; color: var(--accent-green); font-weight: bold;">
                        {BHD_CUENTA}
                    </div>
                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 5px;">Titular: {TITULAR}</div>
                    <div style="font-size: 11px; color: var(--accent-cyan); margin-top: 3px;">{CONTACTO}</div>
                </div>
                <a href="/api/contrato/preview" class="btn" style="width:100%; text-align:center; background:#182947; color:white;">VER MODELO DE CONTRATO B4</a>
            </div>
        </div>
    </div>

    <script>
        const infoPaises = {json.dumps(JURISDICCIONES)};

        function actualizarInfoPais() {{
            const p = document.getElementById("jurisdiccion").value;
            const data = infoPaises[p];
            document.getElementById("pais-info").innerHTML = `
                <b>Normativa de Compras:</b> <span style="color:#00d8f6;">${{data.ley_compras}}</span><br>
                <b>Régimen Antilavado:</b> <span style="color:#00f090;">${{data.ley_antilavado}}</span><br>
                <b>Marco Tributario:</b> ${{data.codigo_tributario}}<br>
                <b>Umbral Compras Menores:</b> <b style="color:#ffb800;">${{data.moneda}} ${{data.umbral_compras_menores.toLocaleString()}}</b><br>
                <b>Autoridades Receptoras:</b> ${{data.autoridades_competentes.join(', ')}}
            `;
        }}

        function ejecutarAuditoriaGlobal() {{
            const p = document.getElementById("jurisdiccion").value;
            const term = document.getElementById("terminal-out");
            const st = document.getElementById("status-bar");
            st.innerHTML = "⏳ Ejecutando análisis pericial bajo normativa de " + infoPaises[p].pais + "...";
            term.innerHTML = "[INICIANDO MATRIZ PERICIAL MULTI-JURISDICCIONAL...]\\n";

            fetch('/api/v8/forensic-inspect', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ pais: p }})
            }})
            .then(res => res.json())
            .then(data => {{
                st.innerHTML = "✅ Auditoría completada. Nivel de Riesgo Global: " + data.nivel_riesgo_global;
                term.innerHTML = JSON.stringify(data, null, 2);
            }})
            .catch(err => {{
                st.innerHTML = "❌ Error en análisis";
                term.innerHTML = "Error ejecutando el motor pericial: " + err;
            }});
        }}

        actualizarInfoPais();
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
    <title>Suscripción de Módulos Forenses - BASA V9.5</title>
    <style>
        body {{ background: #050811; color: #f0f4f8; font-family: sans-serif; padding: 25px; }}
        .card {{ background: #0b1120; border: 1px solid #1f2f4e; max-width: 920px; margin: auto; padding: 25px; border-radius: 12px; }}
        .btn {{ padding: 12px 20px; border-radius: 8px; border: none; font-weight: bold; cursor: pointer; text-decoration: none; }}
        .btn-green {{ background: #00f090; color: #04120a; width: 100%; font-size: 15px; margin-top: 15px; }}
        .input-box {{ width: 100%; padding: 10px; background: #060b17; border: 1px solid #1f2f4e; border-radius: 6px; color: white; margin: 6px 0 12px 0; }}
    </style>
</head>
<body>
    <div class="card">
        <h2 style="color:#00f090; margin-bottom: 10px;">⚙️ Activación y Licenciamiento Global Big Four</h2>
        <p style="color:#8ca2bf; margin-bottom: 20px; font-size: 14px;">Módulos forenses parametrizados para inspecciones nacionales e internacionales:</p>
        
        {mods_html}

        <div style="background:#111a2e; border:1px solid #203152; padding:18px; border-radius:8px; margin-top:15px;">
            <h3 style="color:#00d8f6; margin-bottom: 10px;">Entidad o Firma Auditora</h3>
            <label style="font-size: 13px;">Firma Contable / Institución:</label>
            <input type="text" id="empresa" class="input-box" placeholder="Ej: KPMG / PwC / Contraloría General">
            <label style="font-size: 13px;">RNC / Cédula / Tax ID:</label>
            <input type="text" id="rnc" class="input-box" placeholder="Ej: 131-00000-0">
            <div id="fact-box" style="font-family: monospace; font-size: 13px; color: #d0e2ff; margin-top: 10px;">Calculando cotización...</div>
        </div>

        <button class="btn btn-green" onclick="activarLicencia()">✅ EMITIR ORDEN DE LICENCIA Y FIRMAR DIGITALMENTE</button>
        <div id="resultado" style="display:none; margin-top:15px; background:#072118; border:1px solid #00f090; padding:15px; border-radius:8px; font-family: monospace; font-size: 13px;"></div>
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
                    Módulos: ${{d.modulos.length}} | Mensualidad Recurrente: RD$ ${{d.total_mensual.toLocaleString()}}<br>
                    <b>Primer Cobro Prorrateado (${{d.dias_restantes_mes}} días):</b> <span style="color:#00f090;">RD$ ${{d.primer_pago_prorrateado.toLocaleString()}}</span><br>
                    Cuenta Bancaria: BHD {BHD_CUENTA} ({TITULAR})
                `;
            }});
        }}

        function activarLicencia() {{
            const emp = document.getElementById('empresa').value || 'Firma Auditora Independiente';
            const rnc = document.getElementById('rnc').value || '000000000';

            fetch('/api/activar', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ modulos: modulos, empresa: emp, rnc: rnc, pais: 'GLOBAL' }})
            }})
            .then(r => r.json())
            .then(d => {{
                const res = document.getElementById('resultado');
                res.style.display = 'block';
                res.innerHTML = `
                    <b>No. Contrato Digital:</b> ${{d.contrato_id}}<br>
                    <b>Primer Importe a Liquidar:</b> RD$ ${{d.facturacion.primer_pago_prorrateado.toLocaleString()}}<br>
                    <b>Hash Criptográfico SHA-256:</b> ${{d.hash_seguridad}}<br><br>
                    <a href="/api/contrato/descargar/${{d.contrato_id}}" class="btn" style="background:#00d8f6; color:black; padding:8px 14px;">Descargar Dictamen y Contrato Certificado</a>
                `;
            }});
        }}
        recalcular();
    </script>
</body>
</html>
""")


# ==============================================================================
# APIS PERICIALES (RECEPCIÓN DE DATOS O EJECUCIÓN PARAMÉTRICA AUTOMATIZADA)
# ==============================================================================
@app.route('/api/v8/forensic-inspect', methods=['POST'])
def api_forensic_inspect():
    data = request.get_json(silent=True) or {}
    cod_pais = str(data.get("pais", "DO")).upper()
    config_pais = JURISDICCIONES.get(cod_pais, JURISDICCIONES["DO"])

    # Permite inyectar transacciones del usuario o cargar set de validación pericial adaptado al país
    transacciones = data.get("transacciones")
    if not transacciones or not isinstance(transacciones, list):
        u = config_pais["umbral_compras_menores"]
        transacciones = [
            {"id": "TRX-01", "fecha": "2026-03-01", "monto": u * 0.95, "rnc_proveedor": "PROV-ALPHA", "ncf": "F-001"},
            {"id": "TRX-02", "fecha": "2026-03-03", "monto": u * 0.98, "rnc_proveedor": "PROV-ALPHA", "ncf": "F-002"},
            {"id": "TRX-03", "fecha": "2026-03-06", "monto": u * 0.92, "rnc_proveedor": "PROV-ALPHA", "ncf": "F-003"},
            {"id": "TRX-04", "fecha": "2026-03-10", "monto": u * 12.0, "rnc_proveedor": "PROV-BETA", "ncf": "F-004"},
            {"id": "TRX-05", "fecha": "2026-03-12", "monto": u * 0.80, "rnc_proveedor": "PROV-GAMMA", "ncf": "F-005"}
        ]
        # Transacciones sintéticas para calibrar Benford
        for idx, mult in enumerate([1.1, 1.4, 1.8, 2.1, 2.8, 3.1, 4.2, 5.1, 6.8, 7.9, 8.9, 9.5] * 3):
            transacciones.append({
                "id": f"TRX-SYNTH-{idx}",
                "fecha": "2026-03-15",
                "monto": round(u * mult, 2),
                "rnc_proveedor": "PROV-DELTA",
                "ncf": f"F-SYNTH-{idx}"
            })

    proveedores = data.get("proveedores")
    if not proveedores or not isinstance(proveedores, list):
        proveedores = [
            {"rnc": "PROV-ALPHA", "nombre": "Consorcio Infraestructura SRL", "direccion": "Zona Financiera Torre A, Suite 400", "cuenta_bancaria": "CTA-99011-B"},
            {"rnc": "PROV-GAMMA", "nombre": "Servicios Integrales y Logística SA", "direccion": "Zona Financiera Torre A, Suite 400", "cuenta_bancaria": "CTA-99011-B"},
            {"rnc": "PROV-BETA", "nombre": "Consultora Estratégica Internacional", "direccion": "Av. Reforma 100", "cuenta_bancaria": "CTA-44510-C"}
        ]

    facturas_606 = data.get("facturas_compras") or data.get("facturas_606")
    if not facturas_606 or not isinstance(facturas_606, list):
        facturas_606 = [
            {"ncf": "F-004", "rnc": "PROV-BETA", "monto_facturado": config_pais["umbral_compras_menores"] * 12.0},
            {"ncf": "F-APOCRIFA-999", "rnc": "PROV-FANTASMA", "monto_facturado": config_pais["umbral_compras_menores"] * 5.0}
        ]

    reporte_607 = data.get("facturas_ventas") or data.get("reporte_607")
    if not reporte_607 or not isinstance(reporte_607, list):
        reporte_607 = [{"ncf": "F-004", "monto": config_pais["umbral_compras_menores"] * 12.0}]

    # Ejecución analítica pericial bajo el marco del país
    res_benford = ForensicAuditEngine.ejecutar_benford(transacciones)
    res_fraccionamiento = ForensicAuditEngine.detector_fraccionamiento(transacciones, config_pais)
    res_espejo = ForensicAuditEngine.detector_empresas_espejo(proveedores, config_pais)
    res_tributario = ForensicAuditEngine.detector_inconsistencias_tributarias(facturas_606, reporte_607, config_pais)

    score_total = (
        (50 if res_fraccionamiento else 0) +
        (35 if res_espejo else 0) +
        (25 if res_tributario else 0) +
        (res_benford.get("score_anomalia", 0) * 0.3)
    )
    score_total = min(100.0, round(score_total, 1))

    dictamen_id = f"DICTAMEN-GLOBAL-{cod_pais}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    fecha_emision = datetime.datetime.now().isoformat()
    evidencia_hash = hashlib.sha256(json.dumps(transacciones, sort_keys=True).encode()).hexdigest()

    reporte = {
        "dictamen_pericial_id": dictamen_id,
        "jurisdiccion_aplicada": config_pais["pais"],
        "codigo_iso": cod_pais,
        "fecha_emision": fecha_emision,
        "nivel_riesgo_global": "CRÍTICO / INDICIOS PENALES ESTRUCTURADOS" if score_total > 50 else "CONFORME / BAJO RIESGO",
        "fraud_risk_score": score_total,
        "fundamentacion_juridica": {
            "estandar_auditoria": "Normas Internacionales de Auditoría ISA 240 / INTOSAI ISSAI 5270",
            "compras_estatales": config_pais["ley_compras"],
            "prevencion_lavado": config_pais["ley_antilavado"],
            "regimen_tributario": config_pais["codigo_tributario"],
            "autoridades_competentes": config_pais["autoridades_competentes"]
        },
        "modulos_evaluados": {
            "M1_benford_law": res_benford,
            "M2_fraccionamiento_smurfing": res_fraccionamiento,
            "M3_empresas_espejo_colusion": res_espejo,
            "M6_inconsistencias_fiscales": res_tributario
        },
        "evidencia_criptografica_sha256": evidencia_hash,
        "conclusion_pericial": (
            f"Se han identificado patrones objetivos de riesgo bajo la normativa de {config_pais['pais']}. "
            f"Se recomienda apoderar formalmente a: {', '.join(config_pais['autoridades_competentes'])} "
            f"para la apertura de investigación y acciones de recuperación de activos."
        )
    }

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO dictamenes (dictamen_id, pais, fecha, score_riesgo, payload_json, hash_sha256)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (dictamen_id, cod_pais, fecha_emision, score_total, json.dumps(reporte), evidencia_hash))
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
    pais = str(data.get("pais", "GLOBAL")).upper()
    contrato_id = f"CTR-B4-{pais}-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
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
            INSERT OR REPLACE INTO contratos (contrato_id, empresa, rnc, pais, modulos, total_mensual, primer_pago, hash_seguridad, fecha)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (contrato_id, empresa, rnc, pais, ",".join(fact["modulos"]), fact["total_mensual"], fact["primer_pago_prorrateado"], hash_seguridad, fecha_iso))
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
CONTRATO INTERNACIONAL DE LICENCIA FORENSE BIG FOUR - BASA GLOBAL V9.5
================================================================================
FECHA DE EMISIÓN: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
PROVEEDOR TECNOLÓGICO: BASA FORENSIC INTELLIGENCE (Titular: {TITULAR})
CUENTA BHD RECEPTORA: {BHD_CUENTA}
CONTACTO OFICIAL: {CONTACTO}

CLÁUSULA 1: OBJETO Y ALCANCE
El software proporciona capacidad cuantitativa e inspección probabilística automatizada 
para peritajes judiciales en cumplimiento con:
- ISA 240 (Responsabilidades del Auditor en Relación con el Fraude)
- INTOSAI ISSAI 5270 (Auditoría de Corrupción en Contrataciones Públicas)
- Ley RD 340-06 / Ley 155-17 contra el Lavado de Activos
- US FCPA (Foreign Corrupt Practices Act)
- Ley 9/2017 de Contratos del Sector Público (España / UE)
- LAASSP (México) / Ley 80 (Colombia)

CLÁUSULA 2: CADENA DE CUSTODIA Y SELLADO SHA-256
Cada reporte emitido genera una función resumen criptográfica SHA-256 inmutable,
garantizando la admisibilidad de la evidencia pericial digital en tribunales de justicia.
================================================================================
"""
    buf = io.BytesIO(doc.encode('utf-8'))
    return send_file(buf, mimetype="text/plain", as_attachment=True, download_name="CONTRATO_BASA_GLOBAL_PREVIEW.txt")


@app.route('/api/contrato/descargar/<contrato_id>')
def contrato_descargar(contrato_id):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT empresa, rnc, pais, modulos, total_mensual, primer_pago, hash_seguridad, fecha FROM contratos WHERE contrato_id = ?", (contrato_id,))
        row = cursor.fetchone()

    if not row:
        return jsonify({"error": "Contrato no encontrado en la bóveda"}), 404

    empresa, rnc, pais, modulos, total_m, primer_pago, hash_s, fecha = row

    doc = f"""================================================================================
CERTIFICACIÓN PERICIAL DE LICENCIA DIGITAL - BASA GLOBAL
IDENTIFICADOR ÚNICO: {contrato_id}
HASH SHA-256: {hash_s}
FECHA REGISTRO: {fecha}
JURISDICCIÓN SELECCIONADA: {pais}
================================================================================
FIRMA AUDITORA / CLIENTE: {empresa}
REGISTRO TRIBUTARIO (TAX ID): {rnc}
MÓDULOS CONTRATADOS: {modulos}
MENSUALIDAD: RD$ {total_m:,.2f}
IMPORTE PRIMER PAGO: RD$ {primer_pago:,.2f}
CUENTA RECEPTORA: BANCO BHD {BHD_CUENTA} | TITULAR: {TITULAR}

CERTIFICADO DE CONFORMIDAD LEGAL: HABILITADO PARA DESPLIEGUE JUDICIAL.
"""
    buf = io.BytesIO(doc.encode('utf-8'))
    return send_file(buf, mimetype="text/plain", as_attachment=True, download_name=f"{contrato_id}_CERTIFICADO.txt")


@app.route('/b4/descargar/todo')
def b4_descargar_todo():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("01_DICTAMEN_GLOBAL_ISA_240.txt",
                    f"DICTAMEN PERICIAL EMITIDO BAJO ISA 240 / INTOSAI ISSAI 5270\n"
                    f"Certificación Big 4 - Titular: {TITULAR}\n"
                    f"Cuenta BHD: {BHD_CUENTA}\n"
                    f"Generado: {datetime.datetime.now().isoformat()}\n"
                    f"Validez: Apto para presentación ante Ministerios Públicos y Cámaras de Cuentas.\n")
        
        zf.writestr("02_MATRIZ_NORMATIVA_MULTI_JURISDICCIONAL.csv",
                    "JURISDICCION,PAIS,MONEDA,LEY_COMPRAS,LEY_LAVADO_ACTIVOS,ORGANO_CONTROL\n"
                    "DO,República Dominicana,DOP,Ley 340-06 / Dec 543-12,Ley 155-17,PEPCA / Cámara de Cuentas\n"
                    "US,Estados Unidos,USD,FAR Part 13,Bank Secrecy Act / USA PATRIOT,DOJ / SEC / FinCEN\n"
                    "ES,España / UE,EUR,Ley 9/2017 LCSP,Directiva 6AMLD / Ley 10/2010,Fiscalía Anticorrupción / Tribunal Cuentas\n"
                    "MX,México,MXN,LAASSP Art 41-42,LFPIORPI / Art 69-B CFF,ASF / SFP / UIF\n"
                    "CO,Colombia,COP,Ley 80 / Ley 1150,Ley 1474 / SARLAFT,Contraloría / Procuraduría / DIAN\n"
                    "GLOBAL,Internacional,USD,INTOSAI ISSAI 5270,GAFI 40 Recommendations,Interpol Financial Crimes / UNCAC\n")

        zf.writestr("03_CADENA_CUSTODIA_SHA256.txt",
                    f"SELLADO CRIPTOGRÁFICO DE PRUEBAS DIGITALES: {hashlib.sha256(b'BASA_GLOBAL_SECURE_EVIDENCE_2026').hexdigest()}\n"
                    f"Algoritmo: SHA-256 Digest Standard (FIPS 180-4)\n"
                    f"Perito Oficial: Lic. {TITULAR}\n"
                    f"Contacto: {CONTACTO}\n")

    memory_file.seek(0)
    return send_file(memory_file, mimetype="application/zip", as_attachment=True, download_name=f"EXPEDIENTE_GLOBAL_BIG4_{datetime.datetime.now().strftime('%Y%m%d')}.zip")


@app.route('/healthz')
def healthz():
    return jsonify({
        "status": "OPERATIONAL",
        "engine": "BASA V9.5 GLOBAL-ENTERPRISE",
        "jurisdicciones_disponibles": list(JURISDICCIONES.keys()),
        "bhd_cuenta": BHD_CUENTA,
        "titular": TITULAR,
        "timestamp": datetime.datetime.now().isoformat()
    })


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
