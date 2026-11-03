# -*- coding: utf-8 -*-
"""
================================================================================
BASA FORENSIC INTELLIGENCE - ULTIMATE AUDIT INTELLIGENCE SUITE
Versión: 10.0 USA-GLOBAL ENTERPRISE (Traceable, Independent & Consolidated)
Estándares: PCAOB AS 2401, AICPA SAS 143/145, Yellow Book GAGAS, FinCEN BOI, 
            US False Claims Act, ISA 240, INTOSAI ISSAI 5270, Ley RD 340-06 / 155-17
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
logger = logging.getLogger("BASA_AUDIT_USA")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "basa_sec_audit_usa_2026_enterprise_vault")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# ==============================================================================
# CONFIGURACIÓN BANCARIA Y PARÁMETROS
# ==============================================================================
BHD_CUENTA = os.environ.get("BHD_CUENTA", "08694150021")
TITULAR = os.environ.get("TITULAR_CUENTA", "Pedro Baldera")
CONTACTO = os.environ.get("CONTACTO_OFICIAL", "licpedrobaldera@gmail.com / +1 829 771 7390")
DB_PATH = os.environ.get("BASA_DB_PATH", "basa_audit_traceability.db")

# ==============================================================================
# JURISDICCIONES Y NORMAS USA / INTERNACIONAL
# ==============================================================================
JURISDICCIONES = {
    "US": {
        "pais": "Estados Unidos (USA Standards)", "moneda": "USD",
        "ley_compras": "FAR (Federal Acquisition Regulation Part 13) & False Claims Act (31 U.S.C. § 3729)",
        "ley_antilavado": "Bank Secrecy Act (BSA), FinCEN BOI (Beneficial Ownership) & USA PATRIOT Act",
        "codigo_tributario": "Internal Revenue Code (IRC), Foreign Corrupt Practices Act (FCPA) & SOX Sec. 404/802",
        "auditoria_estandar": "PCAOB AS 2401, AICPA SAS 143/145 & Yellow Book (GAGAS 2024-2026)",
        "umbral_compras_menores": 10000.0,
        "autoridades": ["DOJ (Department of Justice)", "SEC", "FinCEN", "GAO / Inspector General"]
    },
    "DO": {
        "pais": "República Dominicana", "moneda": "DOP",
        "ley_compras": "Ley 340-06 sobre Compras y Contrataciones Públicas y Decreto 543-12",
        "ley_antilavado": "Ley 155-17 contra el Lavado de Activos y Financiamiento del Terrorismo",
        "codigo_tributario": "Código Tributario Ley 11-92 (Formatos 606/607 y Comprobantes Fiscales NCF / e-CF)",
        "auditoria_estandar": "ISA 240, INTOSAI ISSAI 5270 y Normas de la Cámara de Cuentas",
        "umbral_compras_menores": 180000.0,
        "autoridades": ["Cámara de Cuentas", "PEPCA / Procuraduría General", "DGCP", "DIGEIG", "UAF-RD"]
    },
    "ES": {
        "pais": "España & Unión Europea", "moneda": "EUR",
        "ley_compras": "Ley 9/2017 de Contratos del Sector Público (LCSP) - Directivas UE 2014/24",
        "ley_antilavado": "Ley 10/2010 de Prevención de Blanqueo de Capitales y Directiva 6AMLD",
        "codigo_tributario": "Ley General Tributaria 58/2003 y Código Penal Art. 31 bis",
        "auditoria_estandar": "Normas Técnicas de Auditoría NIA-ES 240 y Tribunal de Cuentas Europeo",
        "umbral_compras_menores": 15000.0,
        "autoridades": ["Tribunal de Cuentas", "Fiscalía Anticorrupción", "SEPBLAC", "AEAT"]
    },
    "MX": {
        "pais": "México", "moneda": "MXN",
        "ley_compras": "Ley de Adquisiciones, Arrendamientos y Servicios del Sector Público (LAASSP)",
        "ley_antilavado": "Ley Federal de Prevención de Operaciones con Recursos Ilícitos (LFPIORPI)",
        "codigo_tributario": "Código Fiscal de la Federación (Art. 69-B EFOS/EDOS) y SAT CFDI 4.0",
        "auditoria_estandar": "Normas Internacionales de Auditoría IMCP y Marco ASF",
        "umbral_compras_menores": 350000.0,
        "autoridades": ["Auditoría Superior de la Federación (ASF)", "SFP", "UIF", "SAT"]
    },
    "CO": {
        "pais": "Colombia", "moneda": "COP",
        "ley_compras": "Estatuto General de Contratación (Ley 80 de 1993 y Ley 1150 de 2007)",
        "ley_antilavado": "Estatuto Anticorrupción Ley 1474 de 2011 y Circular Básica Jurídica SARLAFT",
        "codigo_tributario": "Estatuto Tributario Nacional y Facturación Electrónica DIAN",
        "auditoria_estandar": "Normas de Aseguramiento de la Información (NAI) y Contraloría General",
        "umbral_compras_menores": 50000000.0,
        "autoridades": ["Contraloría General", "Procuraduría General", "Fiscalía General", "DIAN"]
    },
    "GLOBAL": {
        "pais": "Marco Internacional ISA / INTOSAI", "moneda": "USD",
        "ley_compras": "INTOSAI ISSAI 5270 (Guideline for Audit of Corruption and Fraud in Procurement)",
        "ley_antilavado": "FATF / GAFI 40 Recommendations on Anti-Money Laundering",
        "codigo_tributario": "Normas Internacionales de Auditoría ISA 240 (Fraude en Estados Financieros)",
        "auditoria_estandar": "International Standards on Auditing (ISA) & Yellow Book",
        "umbral_compras_menores": 10000.0,
        "autoridades": ["UNCAC (Naciones Unidas)", "Interpol Financial Crimes", "INTOSAI"]
    }
}

# ==============================================================================
# CATÁLOGO DE MÓDULOS DE ALTA PRECISIÓN FORENSE
# ==============================================================================
MODULOS_ENTERPRISE = {
    "B4_BASE": {
        "codigo": "B4_BASE",
        "nombre": "B4 Core - Cadena de Custodia Criptográfica, SAS 145 & Matriz ISA 240",
        "precio": 12500, "incluido": True,
        "desc": "Bóveda central de trazabilidad, sellado digital SHA-256 e integridad pericial probatoria."
    },
    "M1_BENFORD": {
        "codigo": "M1_BENFORD",
        "nombre": "M1 - Espectro Benford Chi-Cuadrado de 1er y 2do Dígito (Audit AI USA)",
        "precio": 5500, "incluido": False,
        "desc": "Detección matemática de cifras sintéticas e invención de montos bajo PCAOB AS 2401."
    },
    "M2_FRACCIONAMIENTO": {
        "codigo": "M2_FRACCIONAMIENTO",
        "nombre": "M2 - Algoritmo Anti-Fraccionamiento & Smurfing (FAR Part 13 / Ley 340-06)",
        "precio": 6000, "incluido": False,
        "desc": "Clustering temporal de pagos estructurados para evadir licitaciones públicas obligatorias."
    },
    "M3_EMPRESAS_ESPEJO": {
        "codigo": "M3_EMPRESAS_ESPEJO",
        "nombre": "M3 - Detector FinCEN BOI de Empresas Pantalla, Colusión y Bid-Rigging",
        "precio": 7000, "incluido": False,
        "desc": "Grafo pericial de oferentes con coincidencias en cuentas bancarias, teléfonos o domicilios fiscales."
    },
    "M4_CONFLICTO_INTERES": {
        "codigo": "M4_CONFLICTO_INTERES",
        "nombre": "M4 - Matriz de Consanguinidad, Afinidad con Compradores Públicos y PEPs",
        "precio": 6500, "incluido": False,
        "desc": "Cruce automatizado de funcionarios con beneficiarios reales bajo 18 U.S.C. § 208."
    },
    "M5_NOMINA_FANTASMA": {
        "codigo": "M5_NOMINA_FANTASMA",
        "nombre": "M5 - Auditoría Forense de Nómina: Zombis, TSS Descuadrada y Cuentas Puente",
        "precio": 5000, "incluido": False,
        "desc": "Inspección de pagos a personal desvinculado y dispersión múltiple hacia cuentas bancarias idénticas."
    },
    "M6_EVASION_FISCAL": {
        "codigo": "M6_EVASION_FISCAL",
        "nombre": "M6 - Inconsistencias Fiscales, Comprobantes Apócrifos y Cruce 606/607 / CFDI",
        "precio": 8000, "incluido": False,
        "desc": "Validación cruzada de ventas vs compras declaradas y montos redondos no sustentados."
    },
    "M7_DESVIO_FONDOS": {
        "codigo": "M7_DESVIO_FONDOS",
        "nombre": "M7 - Triangulación a Paraísos Fiscales y Pagos Circulares (BSA / Ley 155-17)",
        "precio": 9000, "incluido": False,
        "desc": "Detección de dispersiones rápidas hacia cuentas offshore y tipologías de blanqueo."
    },
    "M8_QUERELLA_AI": {
        "codigo": "M8_QUERELLA_AI",
        "nombre": "M8 - Generador Automático de Denuncias Penales y Querellas Judiciales",
        "precio": 8500, "incluido": False,
        "desc": "Redacción procesal pericial con citas de leyes aplicables y petitorio de medidas cautelares."
    }
}

# ==============================================================================
# BASE DE DATOS Y BÓVEDA DE TRAZABILIDAD (AUDIT TRAIL)
# ==============================================================================
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS trazabilidad_pericial (
                id_ejecucion TEXT PRIMARY KEY,
                tipo_ejecucion TEXT, -- 'INDIVIDUAL' o 'CONSOLIDADA'
                modulo_o_conjunto TEXT,
                pais TEXT,
                fecha_utc TEXT,
                score_riesgo REAL,
                hash_input TEXT,
                hash_resultado TEXT,
                payload_resultado TEXT
            )
        """)
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

def calcular_hash_objeto(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode('utf-8')).hexdigest()

# ==============================================================================
# MOTOR FORENSE CUANTITATIVO: IMPLEMENTACIÓN INDEPENDIENTE Y TRAZABLE
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
                "modulo": "M1_BENFORD",
                "valido": False,
                "motivo": f"Muestra insuficiente ({n}/20 registros mínimos según PCAOB AS 2401 e ISA 240)",
                "score_anomalia": 0,
                "alteracion_sintetica_detectada": False
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

        alteracion = chi_square > 20.09
        score = min(100.0, round((chi_square / 40.0) * 100, 2))

        return {
            "modulo": "M1_BENFORD",
            "valido": True,
            "estandar_aplicado": "PCAOB AS 2401 / AICPA SAS 145 / ISA 240",
            "total_transacciones": n,
            "chi_cuadrado": round(chi_square, 4),
            "valor_critico_99": 20.09,
            "alteracion_sintetica_detectada": alteracion,
            "score_anomalia": score,
            "distribucion": distribucion,
            "conclusion": "Cifras con desviación probabilística anormal; presunta fabricación manual." if alteracion else "Distribución conforme a la Ley de Benford."
        }

    @staticmethod
    def detector_fraccionamiento(transacciones, config_pais, ventana_dias=15):
        hallazgos = []
        proveedores = collections.defaultdict(list)
        umbral_limite = config_pais["umbral_compras_menores"]
        moneda = config_pais["moneda"]

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
                    individuales_bajo = all(safe_float(x.get("monto", 0)) < umbral_limite for x in cluster)

                    if individuales_bajo and suma >= umbral_limite:
                        ids = sorted([str(x.get("id") or x.get("ncf")) for x in cluster])
                        if ids not in clusters_detectados:
                            clusters_detectados.append(ids)
                            hallazgos.append({
                                "proveedor": rnc,
                                "total_fraccionado": round(suma, 2),
                                "formato_moneda": f"{moneda} {suma:,.2f}",
                                "umbral_evadido": f"{moneda} {umbral_limite:,.2f}",
                                "facturas_detectadas": len(cluster),
                                "evidencias": ids,
                                "normativa_violada": config_pais["ley_compras"],
                                "calificacion_pericial": "Fraccionamiento Ilegal / Smurfing para eludir Licitación Pública"
                            })

        return {
            "modulo": "M2_FRACCIONAMIENTO",
            "total_hallazgos": len(hallazgos),
            "score_riesgo": 100 if hallazgos else 0,
            "detalles": hallazgos,
            "conclusion": f"Se han detectado {len(hallazgos)} patrones de fraccionamiento estructurado." if hallazgos else "No se observan fraccionamientos bajo los umbrales configurados."
        }

    @staticmethod
    def detector_empresas_espejo(proveedores, config_pais):
        anomalias = []
        direcciones = collections.defaultdict(set)
        cuentas = collections.defaultdict(set)

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
                    "patron": "Domicilio fiscal común en oferentes supuestamente competidores",
                    "coincidencia": d,
                    "proveedores_involucrados": list(r_list),
                    "violacion": f"Colusión y Licitación Simulada (Bid-Rigging) / {config_pais['ley_compras']}"
                })

        for c, r_list in cuentas.items():
            if len(r_list) > 1:
                anomalias.append({
                    "patron": "Misma cuenta bancaria de cobro receptora para múltiples RNC/EIN",
                    "coincidencia": c,
                    "proveedores_involucrados": list(r_list),
                    "violacion": f"Empresas Pantalla y Concentración Ilícita FinCEN BOI / {config_pais['ley_antilavado']}"
                })

        return {
            "modulo": "M3_EMPRESAS_ESPEJO",
            "total_anomalias": len(anomalias),
            "score_riesgo": 90 if anomalias else 0,
            "detalles": anomalias,
            "conclusion": f"Se evidencian {len(anomalias)} nexos de cartelización empresarial." if anomalias else "Sin indicios de domicilios o cuentas compartidas."
        }

    @staticmethod
    def detector_conflicto_interes(funcionarios, proveedores):
        hallazgos = []
        nombres_funcionarios = set()
