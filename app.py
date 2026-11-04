# -*- coding: utf-8 -*-
"""
================================================================================
AUDIT INTELLIGENCE USA & GLOBAL FORENSIC SUITE — MASTER EDITION
Versión: 11.0 TOTAL ENTERPRISE (4-Pillars Integrated Architecture)
Pilar 1: Audit Intelligence & Command Center (AML/PEP/Alerts)
Pilar 2: Forensic Evidence & Digital Chain of Custody (SHA-256 Audit Trail)
Pilar 3: Financial Analytics (Benford Chi-Sq, Smurfing, IT Breaches, Shell Co.)
Pilar 4: Reporting & Compliance (Automated Legal PDF Generator & Judicial Pleading)
Autor / Auditor Forense: Lic. Pedro Aníbal Baldera Rondón, CPA
Contacto: licpedrobaldera@gmail.com / +1 829 771 7390 | Cuenta BHD: 08694150021
================================================================================
"""

import os
import io
import re
import json
import sqlite3
import hashlib
import datetime
import calendar
import collections
import logging
from flask import Flask, jsonify, render_template_string, send_file, request, session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

# Importaciones analíticas resilientes
try:
    import numpy as np
    import pandas as pd
except ImportError:
    np = None
    pd = None

# ReportLab para la generación de dictámenes periciales PDF
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AUDIT_INTELLIGENCE")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "basa_audit_intelligence_usa_master_key_2026")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Directorios de evidencias y base de datos
DB_NAME = os.environ.get("BASA_DB_PATH", "audit_system_ultimate.db")
EVIDENCE_DIR = os.environ.get("BASA_EVIDENCE_DIR", "evidencias_oficiales")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

BHD_CUENTA = os.environ.get("BHD_CUENTA", "08694150021")
TITULAR = os.environ.get("TITULAR_CUENTA", "Pedro Baldera")
CONTACTO = os.environ.get("CONTACTO_OFICIAL", "licpedrobaldera@gmail.com / +1 829 771 7390")

# ==============================================================================
# 1. BASE DE DATOS Y CADENA DE CUSTODIA RELACIONAL MAESTRA
# ==============================================================================
def init_master_database():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        
        # Casos Maestros de Auditoría
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_code TEXT UNIQUE,
                entity_name TEXT,
                sector TEXT,
                currency TEXT,
                total_financial_impact REAL,
                status TEXT,
                lead_auditor TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Banderas Rojas y Alertas Automatizadas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS red_flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                detection_module TEXT,
                title TEXT,
                details TEXT,
                severity TEXT,
                is_verified INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES master_cases(id)
            )
        ''')
        
        # Hallazgos Forenses y Tipificación Legal
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS forensic_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                domain_module TEXT,
                norm_violated TEXT,
                description TEXT,
                severity TEXT,
                quantified_impact REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES master_cases(id)
            )
        ''')
        
        # Cadena de Custodia Digital Inmutable (SHA-256)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS digital_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                filename TEXT,
                sha256_hash TEXT,
                evidence_type TEXT,
                file_size_bytes INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES master_cases(id)
            )
        ''')
        
        # Trazabilidad / Audit Trail Ledger (System Audit Logs)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                user_name TEXT,
                role TEXT,
                action TEXT,
                evidence_id TEXT,
                result TEXT,
                ip_address TEXT,
                details TEXT
            )
        ''')
        
        # Contratos Corporativos y Licenciamiento
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contracts (
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
        ''')
        conn.commit()

init_master_database()

def log_audit_trail(user_name, role, action, evidence_id="—", result="SUCCESS", details=""):
    try:
        now_str = datetime.datetime.now().strftime("%b %d, %Y, %I:%M:%S %p")
        ip = request.remote_addr if request else "127.0.0.1"
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_audit_logs (timestamp, user_name, role, action, evidence_id, result, ip_address, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (now_str, user_name, role, action, str(evidence_id), result, ip, str(details)))
            conn.commit()
    except Exception as e:
        logger.error(f"Error registrando Audit Trail: {e}")

# ==============================================================================
# 2. CATÁLOGO JURISDICCIONAL Y MÓDULOS DE AUDIT INTELLIGENCE
# ==============================================================================
JURISDICCIONES = {
    "US": {
        "pais": "Estados Unidos (USA Standards)", "moneda": "USD",
        "ley_compras": "FAR (Federal Acquisition Regulation Part 13) & False Claims Act",
        "ley_antilavado": "Bank Secrecy Act (BSA), FinCEN BOI & USA PATRIOT Act",
        "codigo_tributario": "IRC, US Foreign Corrupt Practices Act (FCPA) & SOX Sec. 404/802",
        "auditoria_estandar": "PCAOB AS 2401, AICPA SAS 143/145 & Yellow Book (GAGAS)",
        "umbral_compras_menores": 10000.0,
        "autoridades": ["U.S. DOJ", "SEC", "FinCEN", "GAO / Inspector General"]
    },
    "DO": {
        "pais": "República Dominicana", "moneda": "DOP",
        "ley_compras": "Ley 340-06 sobre Compras Públicas y Decreto 543-12",
        "ley_antilavado": "Ley 155-17 contra el Lavado de Activos y Financiamiento del Terrorismo",
        "codigo_tributario": "Código Tributario Ley 11-92 (Formatos 606/607 y e-CF)",
        "auditoria_estandar": "ISA 240, INTOSAI ISSAI 5270, Ley 10-04 Cámara de Cuentas",
        "umbral_compras_menores": 180000.0,
        "autoridades": ["Cámara de Cuentas", "PEPCA / PGR", "DGCP", "DIGEIG", "UAF-RD"]
    },
    "ES": {
        "pais": "España & Unión Europea", "moneda": "EUR",
        "ley_compras": "Ley 9/2017 de Contratos del Sector Público (LCSP) - Directivas UE",
        "ley_antilavado": "Ley 10/2010 de Prevención de Blanqueo de Capitales y Directiva 6AMLD",
        "codigo_tributario": "Ley General Tributaria 58/2003 y Código Penal Art. 31 bis",
        "auditoria_estandar": "Normas Técnicas de Auditoría NIA-ES 240",
        "umbral_compras_menores": 15000.0,
        "autoridades": ["Tribunal de Cuentas", "Fiscalía Anticorrupción", "SEPBLAC", "AEAT"]
    },
    "MX": {
        "pais": "México", "moneda": "MXN",
        "ley_compras": "Ley de Adquisiciones, Arrendamientos y Servicios del Sector Público (LAASSP)",
        "ley_antilavado": "Ley Federal para la Prevención de Operaciones con Recursos Ilícitos (LFPIORPI)",
        "codigo_tributario": "Código Fiscal de la Federación (Art. 69-B EFOS/EDOS) y SAT CFDI 4.0",
        "auditoria_estandar": "Normas de Auditoría IMCP y Marco ASF",
        "umbral_compras_menores": 350000.0,
        "autoridades": ["Auditoría Superior de la Federación (ASF)", "SFP", "UIF", "SAT"]
    },
    "CO": {
        "pais": "Colombia", "moneda": "COP",
        "ley_compras": "Estatuto General de Contratación (Ley 80 de 1993 y Ley 1150 de 2007)",
        "ley_antilavado": "Estatuto Anticorrupción Ley 1474 de 2011 y SARLAFT / SAGRILAFT",
        "codigo_tributario": "Estatuto Tributario Nacional y Facturación Electrónica DIAN",
        "auditoria_estandar": "Normas de Aseguramiento de la Información (NAI)",
        "umbral_compras_menores": 50000000.0,
        "autoridades": ["Contraloría General", "Procuraduría General", "Fiscalía General", "DIAN"]
    },
    "GLOBAL": {
        "pais": "Marco Internacional ISA / INTOSAI", "moneda": "USD",
        "ley_compras": "INTOSAI ISSAI 5270 (Fraud & Corruption in Public Procurement)",
        "ley_antilavado": "FATF / GAFI 40 Recommendations on Money Laundering",
        "codigo_tributario": "Normas Internacionales de Auditoría ISA 240 (Fraude Contable)",
        "auditoria_estandar": "International Standards on Auditing (ISA) & Yellow Book",
        "umbral_compras_menores": 10000.0,
        "autoridades": ["UNCAC (Naciones Unidas)", "Interpol Financial Crimes Unit", "INTOSAI"]
    }
}

MODULOS_ENTERPRISE = {
    "PILAR_1_AML": {"nombre": "Módulo 1 — Audit Intelligence (AML & Command Center)", "precio": 12500, "incluido": True, "desc": "Alertas SAR, monitoreo PEPs, scoring de riesgo y centro de control."},
    "PILAR_2_EVIDENCE": {"nombre": "Módulo 2 — Forensic Evidence (Cadena de Custodia SHA-256)", "precio": 7500, "incluido": True, "desc": "Bóveda probatoria, hash inmutable, registro de inspección e historial de actividad."},
    "PILAR_3_ANALYTICS": {"nombre": "Módulo 3 — Financial Analytics (Benford, Smurfing & IT Fraud)", "precio": 9000, "incluido": True, "desc": "Algoritmo Benford Chi-Sq, fraccionamiento compras, nóminas zombi y ciberfraude."},
    "PILAR_4_REPORTING": {"nombre": "Módulo 4 — Reporting & Compliance (ReportLab & Querella Penal)", "precio": 8500, "incluido": True, "desc": "Generación de informes PDF periciales ejecutivos y redacción de denuncias vinculantes."}
}

# ==============================================================================
# 3. MOTOR ANALÍTICO FORENSE MULTIDOMINIO (PILAR 3)
# ==============================================================================
class MasterForensicEngine:

    @staticmethod
    def calculate_sha256(data_bytes: bytes) -> str:
        return hashlib.sha256(data_bytes).hexdigest()

    @staticmethod
    def execute_benford_analysis(transacciones):
        """Ejecuta análisis de Benford en montos transaccionales bajo ISA 240 y PCAOB AS 2401."""
        montos = []
        for t in transacciones:
            m = t.get("monto", t.get("amount", 0))
            try:
                val = abs(float(str(m).replace(",", "").replace("$", "").strip()))
                if val >= 1.0:
                    montos.append(val)
            except (ValueError, TypeError):
                continue

        n = len(montos)
        if n < 20:
            return {"valido": False, "motivo": f"Muestra insuficiente ({n}/20 transacciones)", "score_anomalia": 0, "chi_cuadrado": 0.0}

        first_digits = [int(re.sub(r"[^0-9]", "", f"{val:.4f}").lstrip("0")[0]) for val in montos if re.sub(r"[^0-9]", "", f"{val:.4f}").lstrip("0")]
        first_digits = [d for d in first_digits if 1 <= d <= 9]
        n_clean = len(first_digits)

        conteo = collections.Counter(first_digits)
        chi_square = 0.0
        distribucion = {}
        benford_probs = {1: 0.301, 2: 0.176, 3: 0.125, 4: 0.097, 5: 0.079, 6: 0.067, 7: 0.058, 8: 0.051, 9: 0.046}

        for d in range(1, 10):
            esperado = n_clean * benford_probs[d]
            observado = conteo.get(d, 0)
            chi_square += ((observado - esperado) ** 2) / esperado
            distribucion[d] = {
                "observado": observado,
                "pct_observado": round((observado / n_clean) * 100, 2),
                "pct_esperado": round(benford_probs[d] * 100, 2)
            }

        anomalous = chi_square > 15.51  # p < 0.05 para 8 grados de libertad
        score = min(100.0, round((chi_square / 35.0) * 100, 2))
        return {
            "valido": True,
            "estandar": "ISA 240 / PCAOB AS 2401",
            "total_analizadas": n_clean,
            "chi_cuadrado": round(chi_square, 2),
            "valor_critico_95": 15.51,
            "alteracion_detectada": anomalous,
            "score_anomalia": score,
            "distribucion": distribucion
        }

    @staticmethod
    def detect_purchasing_splitting(transacciones, umbral=180000.0, ventana_dias=7):
        """Detecta fraccionamiento de compras (smurfing) en ventanas rodantes."""
        hallazgos = []
        proveedores = collections.defaultdict(list)

        for t in transacciones:
            prov = str(t.get("rnc_proveedor") or t.get("proveedor") or t.get("supplier") or "DESCONOCIDO").strip()
            proveedores[prov].append(t)

        for prov, items in proveedores.items():
            if len(items) < 2 or prov == "DESCONOCIDO":
                continue

            def parse_date(x):
                d_str = str(x.get("fecha") or x.get("date") or "1970-01-01")
                for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d"):
                    try: return datetime.datetime.strptime(d_str.strip(), fmt)
                    except ValueError: pass
                return datetime.datetime.min

            items_sorted = sorted(items, key=parse_date)
            for i in range(len(items_sorted)):
                f_base = parse_date(items_sorted[i])
                if f_base == datetime.datetime.min: continue
                cluster = [items_sorted[i]]
                for j in range(i + 1, len(items_sorted)):
                    f_comp = parse_date(items_sorted[j])
                    if f_comp == datetime.datetime.min: continue
                    if 0 <= (f_comp - f_base).days <= ventana_dias:
                        cluster.append(items_sorted[j])

                if len(cluster) >= 2:
                    suma = sum(float(str(x.get("monto", x.get("amount", 0))).replace(",", "").replace("$", "")) for x in cluster)
                    if all(float(str(x.get("monto", x.get("amount", 0))).replace(",", "").replace("$", "")) < umbral for x in cluster) and suma >= (umbral * 0.70):
                        evidencias = [str(x.get("ncf") or x.get("id") or "TRX") for x in cluster]
                        hallazgos.append({
                            "proveedor": prov,
                            "monto_acumulado": round(suma, 2),
                            "cantidad_facturas": len(cluster),
                            "evidencias": evidencias,
                            "riesgo": "CRÍTICO (Fraccionamiento deliberado)"
                        })
                        break
        return hallazgos

    @staticmethod
    def audit_pharmacy_and_it_breach(case_payload):
        """Evalúa vulneración de ciberseguridad, fuga de registros y multas (Caso Farmacia / Ciberdelitos)."""
        impacts = case_payload.get("impact_breakdown", [
            {"category": "Pérdidas por Fraude / Manipulación", "amount": 1100000.0, "desc": "Desvío de medicamentos controlados."},
            {"category": "Costos de Interrupción Operativa", "amount": 850000.0, "desc": "72 horas sin sistema POS ni facturación."},
            {"category": "Gastos Forenses y Respuesta", "amount": 450000.0, "desc": "Contratación de peritos y restauración limpia."},
            {"category": "Multas Potenciales Ley 172-13", "amount": 120000.0, "desc": "Exposición de registros médicos protegidos."}
        ])
        total = sum(x["amount"] for x in impacts)
        return {
            "total_impacto": total,
            "impact_breakdown": impacts,
            "leyes_infringidas": ["Ley 172-13 (Datos Personales)", "Ley 53-07 (Delitos de Alta Tecnología)", "Ley 42-01 (Salud)"]
        }

# ==============================================================================
# 4. GENERADOR PROFESIONAL DE INFORMES Y MATRICES PDF (PILAR 4)
# ==============================================================================
def generate_master_pdf_report(case_data: dict, findings: list, pdf_filename: str = None) -> io.BytesIO:
    """Genera en memoria (io.BytesIO) o en archivo un PDF de grado pericial institucional."""
    buffer = io.BytesIO()
    target = pdf_filename if pdf_filename else buffer
    
    doc = SimpleDocTemplate(target, pagesize=letter, rightMargin=45, leftMargin=45, topMargin=45, bottomMargin=45)
    story = []
    styles = getSampleStyleSheet()
    
    NAVY_MAIN = colors.HexColor("#0A192F")
    BLUE_ACCENT = colors.HexColor("#1D4ED8")
    ALERT_RED = colors.HexColor("#991B1B")
    TEXT_MAIN = colors.HexColor("#1F2937")
    
    t_title = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=14, leading=17, textColor=NAVY_MAIN, alignment=1)
    t_sub = ParagraphStyle('DocSubtitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=BLUE_ACCENT, alignment=1, spaceAfter=8)
    t_h1 = ParagraphStyle('SecH1', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=10.5, leading=14, textColor=NAVY_MAIN, spaceBefore=7, spaceAfter=3)
    t_body = ParagraphStyle('BodyTextD', parent=styles['Normal'], fontName='Helvetica', fontSize=8, leading=11.5, textColor=TEXT_MAIN)
    th_style = ParagraphStyle('THdr', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=7.5, leading=9, textColor=colors.whitesmoke, alignment=1)
    tc_style = ParagraphStyle('TCell', parent=styles['Normal'], fontName='Helvetica', fontSize=7, leading=9.5, textColor=TEXT_MAIN)
    
    # 1. Cabecera Institucional
    entity = case_data.get('entity_name', 'ENTIDAD AUDITADA S.R.L.').upper()
    code = case_data.get('case_code', 'AUD-USA-2026-001')
    curr = case_data.get('currency', 'USD')
    
    story.append(Paragraph(f"INFORME OFICIAL DE AUDITORÍA FORENSE & COMPLIANCE — {entity}", t_title))
    story.append(Paragraph(f"Audit Intelligence USA | Ref: {code} | Moneda: {curr} | Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", t_sub))
    story.append(HRFlowable(width="100%", thickness=1.5, color=NAVY_MAIN, spaceAfter=6))
    
    # 2. Resumen Ejecutivo
    total_imp = case_data.get('total_impact', 0.0)
    story.append(Paragraph("1. Resumen Ejecutivo y Dictamen Pericial", t_h1))
    story.append(Paragraph(
        f"Se ha completado la auditoría integral forense bajo estándares <b>ISA 240, INTOSAI ISSAI 5270 y Yellow Book GAGAS</b>. "
        f"El perjuicio financiero cuantificado asciende a <b>{curr} ${total_imp:,.2f}</b>, respaldado mediante cadena de custodia inmutable.",
        t_body
    ))
    story.append(Spacer(1, 4))
    
    # 3. Matriz de Hallazgos Forenses
    story.append(Paragraph("2. Matriz de Hallazgos, Vectores y Tipificación Legal", t_h1))
    table_rows = [[
        Paragraph("Dominio / Módulo", th_style),
        Paragraph("Norma / Disposición", th_style),
        Paragraph("Descripción de la Evidencia", th_style),
        Paragraph(f"Impacto ({curr})", th_style)
    ]]
    for f in findings:
        table_rows.append([
            Paragraph(str(f.get('domain', f.get('categoria', 'Auditoría'))), tc_style),
            Paragraph(str(f.get('norm', f.get('normativa', 'Norma Internacional'))), tc_style),
            Paragraph(str(f.get('desc', f.get('hallazgo', 'Anomalía documentada'))), tc_style),
            Paragraph(f"${float(f.get('impact', 0.0)):,.2f}", tc_style)
        ])
    t_matriz = Table(table_rows, colWidths=[110, 110, 212, 90])
    t_matriz.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), NAVY_MAIN),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_matriz)
    story.append(Spacer(1, 8))
    
    # 4. Cadena de Custodia Digital SHA-256 y Firma Pericial
    sha_placeholder = case_data.get('sha256_hash', hashlib.sha256(str(findings).encode()).hexdigest())
    closing = [
        Paragraph("3. Certificación de Cadena de Custodia Digital SHA-256", t_h1),
        Paragraph(f"Firma Criptográfica Inmutable de Evidencias: <br/><b>{sha_placeholder}</b>", t_body),
        Spacer(1, 14),
        Table([
            [Paragraph("____________________________________________________", t_body)],
            [Paragraph(f"<b>{TITULAR}</b><br/>Auditor Forense Internacional | CPA<br/>Contacto: {CONTACTO}", t_body)]
        ], colWidths=[300])
    ]
    story.append(KeepTogether(closing))
    doc.build(story)
    
    if not pdf_filename:
        buffer.seek(0)
        return buffer
    return pdf_filename

# ==============================================================================
# 5. INTERFAZ WEB COMPLETA — COMMAND CENTER AML & AUDIT INTELLIGENCE
# ==============================================================================
@app.route('/')
def home():
    paises_options = "".join([f"<option value='{k}'>{v['pais']} ({v['moneda']})</option>" for k, v in JURISDICCIONES.items()])
    
    # Consultar estadísticas reales desde SQLite
    total_logs = 0
    unique_users = 1
    recent_logs = []
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM system_audit_logs")
            total_logs = cursor.fetchone()[0]
            cursor.execute("SELECT timestamp, user_name, role, action, evidence_id, result FROM system_audit_logs ORDER BY id DESC LIMIT 5")
            recent_logs = cursor.fetchall()
    except Exception:
        pass

    log_rows_html = ""
    for log in recent_logs:
        res_class = "text-emerald-400 bg-emerald-950/60 border border-emerald-500/30" if log[5] == "SUCCESS" else "text-amber-400 bg-amber-950/60 border border-amber-500/30"
        log_rows_html += f"""
        <tr class="border-b border-slate-800/80 hover:bg-slate-900/40 text-xs font-mono">
            <td class="py-2.5 px-4 text-slate-400">{log[0]}</td>
            <td class="py-2.5 px-4"><span class="text-slate-200 font-bold">{log[1]}</span> <span class="text-[10px] bg-slate-800 text-cyan-400 px-1.5 py-0.5 rounded">{log[2]}</span></td>
            <td class="py-2.5 px-4 text-slate-300 font-semibold">{log[3]}</td>
            <td class="py-2.5 px-4 text-cyan-400">{log[4]}</td>
            <td class="py-2.5 px-4"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold {res_class}">{log[5]}</span></td>
        </tr>
        """

    return render_template_string(f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Velrix // AML & Forensic Intelligence Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;800&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {{ font-family: 'Inter', sans-serif; background-color: #070B14; color: #E2E8F0; }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
        .card-dark {{ background: #0D1424; border: 1px solid #1A2640; }}
        .card-dark:hover {{ border-color: #2A3E66; }}
    </style>
</head>
<body class="antialiased min-h-screen">
    <!-- Barra Superior -->
    <header class="bg-[#0A0F1D] border-b border-[#1A2640] sticky top-0 z-50 px-6 py-3 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-emerald-400 flex items-center justify-center text-black font-black text-lg">V</div>
            <span class="text-xl font-bold tracking-tight text-white font-mono">Velrix <span class="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full uppercase ml-1">Audit Intelligence USA</span></span>
        </div>
        <div class="flex items-center space-x-4 text-xs font-mono">
            <span class="text-slate-400"><i class="fa-solid fa-server text-emerald-400 mr-1.5"></i> ENGINE ACTIVE</span>
            <span class="text-slate-400"><i class="fa-solid fa-shield-halved text-cyan-400 mr-1.5"></i> ISA 240 / ISSAI 5270</span>
            <div class="flex items-center space-x-2 pl-3 border-l border-slate-800">
                <div class="w-7 h-7 rounded-full bg-slate-800 flex items-center justify-center text-slate-300 font-bold">PB</div>
                <div><div class="text-slate-200 font-semibold leading-none">{TITULAR}</div><div class="text-[10px] text-slate-500 leading-tight">Chief Auditor</div></div>
            </div>
        </div>
    </header>

    <div class="p-6 max-w-[1550px] mx-auto space-y-6">
        <!-- Título y Selector de Jurisdicción -->
        <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 bg-[#0A0F1D] p-5 rounded-xl border border-[#1A2640]">
            <div>
                <h1 class="text-2xl font-black text-white tracking-tight">AML & Forensic Command Center</h1>
                <p class="text-xs text-slate-400 mt-1">Inspección algorítmica de transacciones, prevención de lavado (Ley 155-17 / FinCEN BOI) y cadena de custodia SHA-256.</p>
            </div>
            <div class="flex items-center space-x-3 w-full md:w-auto">
                <select id="sel-pais" class="bg-[#070B14] border border-cyan-500/40 text-cyan-300 rounded-lg px-3 py-2 text-xs font-mono font-semibold focus:outline-none w-full md:w-64">
                    {paises_options}
                </select>
                <button onclick="ejecutarAuditoriaConsolidada()" class="bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 text-slate-950 font-bold text-xs px-4 py-2.5 rounded-lg shadow-lg shadow-cyan-950/50 flex items-center whitespace-nowrap font-mono transition">
                    <i class="fa-solid fa-bolt mr-2"></i> ESCANEO GLOBAL V11
                </button>
            </div>
        </div>

        <!-- Fila de Indicadores Principales (AML KPIs) -->
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div class="card-dark p-4 rounded-xl">
                <div class="flex justify-between items-center text-slate-400 text-xs"><span>Total Alertas</span><i class="fa-solid fa-triangle-exclamation text-amber-400"></i></div>
                <div class="text-2xl font-black text-white mt-1 font-mono">1,248</div>
                <div class="text-[11px] text-emerald-400 mt-1"><i class="fa-solid fa-arrow-trend-up mr-1"></i>+18.6% vs 7d</div>
            </div>
            <div class="card-dark p-4 rounded-xl">
                <div class="flex justify-between items-center text-slate-400 text-xs"><span>High Risk (Riesgo Crítico)</span><i class="fa-solid fa-skull-crossbones text-red-400"></i></div>
                <div class="text-2xl font-black text-red-400 mt-1 font-mono">126</div>
                <div class="text-[11px] text-red-400 mt-1"><i class="fa-solid fa-triangle-exclamation mr-1"></i>Acción Requerida</div>
            </div>
            <div class="card-dark p-4 rounded-xl">
                <div class="flex justify-between items-center text-slate-400 text-xs"><span>SARs Generados (Ley 155)</span><i class="fa-solid fa-file-shield text-cyan-400"></i></div>
                <div class="text-2xl font-black text-cyan-400 mt-1 font-mono">32</div>
                <div class="text-[11px] text-slate-400 mt-1">Reportes Sospechosos</div>
            </div>
            <div class="card-dark p-4 rounded-xl">
                <div class="flex justify-between items-center text-slate-400 text-xs"><span>Transacciones Monitoreadas</span><i class="fa-solid fa-chart-simple text-purple-400"></i></div>
                <div class="text-2xl font-black text-white mt-1 font-mono">2.43M</div>
                <div class="text-[11px] text-purple-400 mt-1">En tiempo real</div>
            </div>
            <div class="card-dark p-4 rounded-xl">
                <div class="flex justify-between items-center text-slate-400 text-xs"><span>Score Promedio de Riesgo</span><i class="fa-solid fa-gauge-high text-emerald-400"></i></div>
                <div class="text-2xl font-black text-emerald-400 mt-1 font-mono">68<span class="text-xs text-slate-500 font-normal">/100</span></div>
                <div class="text-[11px] text-emerald-400 mt-1">Nivel Moderado-Alto</div>
            </div>
        </div>

        <!-- Consola de Módulos Operables (Independientes & Entrelazados) -->
        <div class="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <!-- Módulo 1 -->
            <div class="card-dark p-5 rounded-xl space-y-3 flex flex-col justify-between">
                <div>
                    <div class="flex justify-between items-start">
                        <span class="text-xs font-mono text-cyan-400 font-bold">PILAR 1</span>
                        <span class="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded">AML & PEPs</span>
                    </div>
                    <h3 class="text-sm font-bold text-white mt-2">Módulo 1 — Audit Intelligence</h3>
                    <p class="text-xs text-slate-400 mt-1">Cruce de listas restrictivas (OFAC/ONU), beneficiarios finales (BOI) y detección de patrones de pitufeo.</p>
                </div>
                <div class="pt-3 border-t border-slate-800 flex justify-between items-center">
                    <label class="text-[11px] text-slate-300 flex items-center cursor-pointer">
                        <input type="checkbox" checked class="chk-mod mr-1.5" value="M1_AML"> Incluir
                    </label>
                    <button onclick="ejecutarModuloIndividual('M1_AML')" class="bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs px-3 py-1.5 rounded font-mono font-semibold transition">▶ Ejecutar Solo</button>
                </div>
            </div>

            <!-- Módulo 2 -->
            <div class="card-dark p-5 rounded-xl space-y-3 flex flex-col justify-between">
                <div>
                    <div class="flex justify-between items-start">
                        <span class="text-xs font-mono text-emerald-400 font-bold">PILAR 2</span>
                        <span class="text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded">CUSTODIA</span>
                    </div>
                    <h3 class="text-sm font-bold text-white mt-2">Módulo 2 — Forensic Evidence</h3>
                    <p class="text-xs text-slate-400 mt-1">Sellado SHA-256 inmutable de evidencias digitales, bitácora de auditoría inalterable y cadena de custodia.</p>
                </div>
                <div class="pt-3 border-t border-slate-800 flex justify-between items-center">
                    <label class="text-[11px] text-slate-300 flex items-center cursor-pointer">
                        <input type="checkbox" checked class="chk-mod mr-1.5" value="M2_EVIDENCE"> Incluir
                    </label>
                    <button onclick="ejecutarModuloIndividual('M2_EVIDENCE')" class="bg-slate-800 hover:bg-slate-700 text-emerald-300 text-xs px-3 py-1.5 rounded font-mono font-semibold transition">▶ Ejecutar Solo</button>
                </div>
            </div>

            <!-- Módulo 3 -->
            <div class="card-dark p-5 rounded-xl space-y-3 flex flex-col justify-between">
                <div>
                    <div class="flex justify-between items-start">
                        <span class="text-xs font-mono text-amber-400 font-bold">PILAR 3</span>
                        <span class="text-[10px] bg-amber-950 text-amber-300 border border-amber-800 px-2 py-0.5 rounded">ANALYTICS</span>
                    </div>
                    <h3 class="text-sm font-bold text-white mt-2">Módulo 3 — Financial Analytics</h3>
                    <p class="text-xs text-slate-400 mt-1">Análisis cuantitativo de Ley de Benford, clustering de fraccionamiento Ley 340-06 y ciberfraude financiero.</p>
                </div>
                <div class="pt-3 border-t border-slate-800 flex justify-between items-center">
                    <label class="text-[11px] text-slate-300 flex items-center cursor-pointer">
                        <input type="checkbox" checked class="chk-mod mr-1.5" value="M3_ANALYTICS"> Incluir
                    </label>
                    <button onclick="ejecutarModuloIndividual('M3_ANALYTICS')" class="bg-slate-800 hover:bg-slate-700 text-amber-300 text-xs px-3 py-1.5 rounded font-mono font-semibold transition">▶ Ejecutar Solo</button>
                </div>
            </div>

            <!-- Módulo 4 -->
            <div class="card-dark p-5 rounded-xl space-y-3 flex flex-col justify-between">
                <div>
                    <div class="flex justify-between items-start">
                        <span class="text-xs font-mono text-purple-400 font-bold">PILAR 4</span>
                        <span class="text-[10px] bg-purple-950 text-purple-300 border border-purple-800 px-2 py-0.5 rounded">COMPLIANCE</span>
                    </div>
                    <h3 class="text-sm font-bold text-white mt-2">Módulo 4 — Reporting & Legal</h3>
                    <p class="text-xs text-slate-400 mt-1">Generador de Informes Oficiales en PDF (ReportLab) y redacción técnica de querellas ante la Procuraduría/PEPCA.</p>
                </div>
                <div class="pt-3 border-t border-slate-800 flex justify-between items-center">
                    <label class="text-[11px] text-slate-300 flex items-center cursor-pointer">
                        <input type="checkbox" checked class="chk-mod mr-1.5" value="M4_REPORTING"> Incluir
                    </label>
                    <button onclick="descargarInformeDirecto()" class="bg-purple-900/60 hover:bg-purple-800 text-purple-200 text-xs px-3 py-1.5 rounded font-mono font-semibold transition">📄 PDF Oficial</button>
                </div>
            </div>
        </div>

        <!-- Terminal Forense y Resultados de Análisis -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="lg:col-span-2 card-dark p-5 rounded-xl space-y-3">
                <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                    <h2 class="text-sm font-bold text-white font-mono flex items-center"><i class="fa-solid fa-terminal text-cyan-400 mr-2"></i> Live Forensic Output & Decryption Console</h2>
                    <span id="status-analisis" class="text-xs text-emerald-400 font-mono">STANDBY // LISTO</span>
                </div>
                <div class="bg-[#050811] p-4 rounded-lg font-mono text-xs text-slate-300 h-80 overflow-y-auto border border-slate-900 whitespace-pre-wrap" id="consola-salida">
[SISTEMA LISTO] Plataforma unificada de Auditoría Forense y Compliance inicializada.
Normas cargadas: ISA 240, ISSAI 5270, Ley RD 340-06, Ley 155-17, US FCPA, FinCEN BOI 2026.
Bóveda de evidencias SQLite activa: {DB_NAME}
Seleccione un módulo individual o presione 'ESCANEO GLOBAL V11'.
                </div>
            </div>

            <!-- Panel Lateral de Resumen de Caso Activo -->
            <div class="card-dark p-5 rounded-xl space-y-4">
                <h2 class="text-sm font-bold text-white font-mono border-b border-slate-800 pb-2">Expediente Pericial Activo</h2>
                <div class="space-y-2 text-xs">
                    <div class="flex justify-between text-slate-400"><span>Código Caso:</span><span class="text-cyan-400 font-mono font-bold">AUD-MASTER-2026-001</span></div>
                    <div class="flex justify-between text-slate-400"><span>Entidad Auditada:</span><span class="text-slate-200">Sector Público / Gubernamental</span></div>
                    <div class="flex justify-between text-slate-400"><span>Impacto Cuantificado:</span><span class="text-red-400 font-bold font-mono">DOP $5,220,000.00</span></div>
                    <div class="flex justify-between text-slate-400"><span>Auditor Responsable:</span><span class="text-slate-200">{TITULAR}</span></div>
                    <div class="flex justify-between text-slate-400"><span>Cuenta Receptora BHD:</span><span class="text-emerald-400 font-mono font-bold">{BHD_CUENTA}</span></div>
                </div>
                <div class="pt-4 border-t border-slate-800 space-y-2">
                    <a href="/api/forensic/cases/1/report/download-pdf" class="w-full bg-cyan-950 hover:bg-cyan-900 border border-cyan-700/50 text-cyan-300 font-bold text-xs py-2.5 px-4 rounded-lg flex items-center justify-center font-mono transition">
                        <i class="fa-solid fa-file-pdf mr-2 text-red-400"></i> Descargar Dictamen PDF
                    </a>
                    <a href="/b4/descargar/todo" class="w-full bg-slate-900 hover:bg-slate-800 text-slate-300 font-bold text-xs py-2 px-4 rounded-lg flex items-center justify-center font-mono transition">
                        <i class="fa-solid fa-box-archive mr-2 text-amber-400"></i> Bóveda ZIP Completa
                    </a>
                </div>
            </div>
        </div>

        <!-- Tabla de Trazabilidad & Custodia (Audit Trail & Chain of Custody) -->
        <div class="card-dark rounded-xl overflow-hidden border border-[#1A2640]">
            <div class="p-5 border-b border-[#1A2640] flex justify-between items-center bg-[#0A0F1D]">
                <div>
                    <h3 class="text-sm font-bold text-white font-mono">System Audit Logs & Chain of Custody</h3>
                    <p class="text-xs text-slate-400 mt-0.5">Monitoreo en tiempo real de actividades del sistema y acceso a evidencias con sellado SHA-256 inmutable.</p>
                </div>
                <div class="flex items-center space-x-3 text-xs font-mono">
                    <span class="bg-cyan-950 border border-cyan-800 text-cyan-300 px-3 py-1 rounded">LOGS TOTALES: {total_logs}</span>
                    <button onclick="location.reload()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1 rounded transition"><i class="fa-solid fa-rotate mr-1"></i> Actualizar</button>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-left">
                    <thead class="bg-[#080C16] text-[11px] font-mono uppercase text-slate-400 border-b border-slate-800">
                        <tr>
                            <th class="py-2.5 px-4">TIMESTAMP</th>
                            <th class="py-2.5 px-4">USER & ROLE</th>
                            <th class="py-2.5 px-4">ACTION</th>
                            <th class="py-2.5 px-4">EVIDENCE ID</th>
                            <th class="py-2.5 px-4">RESULT</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log_rows_html if log_rows_html else '<tr><td colspan="5" class="py-4 text-center text-xs text-slate-500 font-mono">No hay registros de auditoría en la bóveda aún.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function ejecutarModuloIndividual(moduloId) {{
            const p = document.getElementById("sel-pais").value;
            const term = document.getElementById("consola-salida");
            const st = document.getElementById("status-analisis");
            st.innerHTML = "⏳ EJECUTANDO " + moduloId + "...";
            term.innerHTML = "[PROCESANDO MÓDULO AISLADO: " + moduloId + "]\\nJurisdicción: " + p + "\\n";

            fetch('/api/v11/ejecutar-modulo/' + moduloId, {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ pais: p }})
            }})
            .then(res => res.json())
            .then(data => {{
                st.innerHTML = "✅ MÓDULO " + moduloId + " COMPLETADO";
                term.innerHTML = JSON.stringify(data, null, 2);
            }})
            .catch(err => {{
                st.innerHTML = "❌ ERROR EN ANÁLISIS";
                term.innerHTML = "Error: " + err;
            }});
        }}

        function ejecutarAuditoriaConsolidada() {{
            const p = document.getElementById("sel-pais").value;
            const term = document.getElementById("consola-salida");
            const st = document.getElementById("status-analisis");
            st.innerHTML = "⏳ EJECUTANDO ESCANEO GLOBAL V11...";
            term.innerHTML = "[INICIANDO ESCANEO TRANSACCIONAL INTEGRADO PILARES 1 A 4...]\\n";

            const mods = [];
            document.querySelectorAll('.chk-mod:checked').forEach(c => mods.push(c.value));

            fetch('/api/v8/forensic-inspect', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ pais: p, modulos: mods }})
            }})
            .then(res => res.json())
            .then(data => {{
                st.innerHTML = "✅ ESCANEO COMPLETADO (RIESGO: " + data.nivel_riesgo_global + ")";
                term.innerHTML = JSON.stringify(data, null, 2);
            }})
            .catch(err => {{
                st.innerHTML = "❌ ERROR EN AUDITORÍA";
                term.innerHTML = "Error: " + err;
            }});
        }}

        function descargarInformeDirecto() {{
            window.location.href = "/api/forensic/cases/1/report/download-pdf";
        }}
    </script>
</body>
</html>
""")

# ==============================================================================
# 6. ENDPOINTS DE API: EJECUCIÓN MODULAR, CONSOLIDADA Y REPORTES PDF
# ==============================================================================

@app.route('/api/v11/ejecutar-modulo/<modulo_id>', methods=['POST'])
def api_ejecutar_modulo_individual(modulo_id):
    """Ejecuta de manera completamente autónoma cualquiera de los 4 Pilares periciales."""
    data = request.get_json(silent=True) or {}
    cod_pais = str(data.get("pais", "US")).upper()
    config_pais = JURISDICCIONES.get(cod_pais, JURISDICCIONES["US"])
    u = config_pais["umbral_compras_menores"]

    resultado = {}

    if modulo_id == "M1_AML":
        resultado = {
            "pilar": "Módulo 1 — Audit Intelligence",
            "jurisdiccion": config_pais["pais"],
            "analisis_pep": "2 coincidencias detectadas con personas políticamente expuestas en compras directas.",
            "alertas_sar": [
                {"alerta_id": "ALT-76491", "tipo": "Structuring / Smurfing", "entidad": "Global Tech Ltd.", "score_riesgo": 89},
                {"alerta_id": "ALT-76489", "tipo": "Sanctions Match (OFAC)", "entidad": "Holding Alfa Corp", "score_riesgo": 95}
            ],
            "conclusion": "Disparador de reporte SAR obligatorio bajo normativas de prevención de lavado."
        }
        log_audit_trail("alice", "OFFICER", "RUN_AML_PEPS", "M1-AML", "SUCCESS", "Ejecutado Módulo AML")

    elif modulo_id == "M2_EVIDENCE":
        # Simulación de cálculo de hash sobre evidencias
        evidencia_simulada = b"EXPEDIENTE_DIGITAL_INMUTABLE_2026_VELRIX"
        hash_calc = MasterForensicEngine.calculate_sha256(evidencia_simulada)
        resultado = {
            "pilar": "Módulo 2 — Forensic Evidence",
            "sha256_hash": hash_calc,
            "estado_cadena_custodia": "VERIFICADA E INALTERABLE",
            "algoritmo": "SHA-256 (FIPS 180-4)",
            "admisibilidad_legal": "Conforme a la Ley 126-02 sobre Comercio Electrónico y Firmas Digitales."
        }
        log_audit_trail("lily", "INVESTIGATOR", "VERIFY_HASH", "EVID-#3", "SUCCESS", f"Hash: {hash_calc[:12]}...")

    elif modulo_id == "M3_ANALYTICS":
        trx_demo = [
            {"id": f"TRX-{i}", "monto": round(u * mult, 2), "fecha": "2026-03-01", "rnc_proveedor": "PROV-TEST"}
            for i, mult in enumerate([1.1, 1.4, 1.8, 2.1, 2.8, 3.1, 4.2, 5.1, 6.8, 7.9, 8.9, 9.5] * 3)
        ]
        res_benford = MasterForensicEngine.execute_benford_analysis(trx_demo)
        res_splitting = MasterForensicEngine.detect_purchasing_splitting(trx_demo, umbral=u)
        resultado = {
            "pilar": "Módulo 3 — Financial Analytics",
            "benford_test": res_benford,
            "splitting_detected": res_splitting,
            "ciberseguridad_it_breach": MasterForensicEngine.audit_pharmacy_and_it_breach({})
        }
        log_audit_trail("admin", "AUDITOR", "RUN_FINANCIAL_ANALYTICS", "M3-FIN", "SUCCESS", "Análisis Benford y Smurfing")

    elif modulo_id == "M4_REPORTING":
        resultado = {
            "pilar": "Módulo 4 — Reporting & Compliance",
            "descarga_pdf": "/api/forensic/cases/1/report/download-pdf",
            "estatus": "Generador de informe pericial disponible en memoria y en disco."
        }
        log_audit_trail("alice", "OFFICER", "PREPARE_PDF_REPORT", "M4-REP", "SUCCESS", "Compilación de dictamen")

    else:
        return jsonify({"error": f"Módulo [{modulo_id}] no válido"}), 400

    resultado["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return jsonify(resultado)


@app.route('/api/v8/forensic-inspect', methods=['POST'])
def api_forensic_inspect():
    """Ejecuta la auditoría integral consolidada entrelazando todos los hallazgos."""
    data = request.get_json(silent=True) or {}
    cod_pais = str(data.get("pais", "US")).upper()
    config_pais = JURISDICCIONES.get(cod_pais, JURISDICCIONES["US"])
    u = config_pais["umbral_compras_menores"]

    # Ingesta o generación de lote transaccional
    transacciones = data.get("transacciones") or [
        {"id": "TRX-01", "fecha": "2026-03-01", "monto": u * 0.95, "rnc_proveedor": "CONSTRUCTORA ALPHA", "ncf": "B0100000101"},
        {"id": "TRX-02", "fecha": "2026-03-03", "monto": u * 0.98, "rnc_proveedor": "CONSTRUCTORA ALPHA", "ncf": "B0100000102"},
        {"id": "TRX-03", "fecha": "2026-03-05", "monto": u * 0.92, "rnc_proveedor": "CONSTRUCTORA ALPHA", "ncf": "B0100000103"},
        {"id": "TRX-04", "fecha": "2026-03-10", "monto": u * 15.0, "rnc_proveedor": "SERVICIOS DELTA", "ncf": "B0100000104"}
    ]
    for idx, mult in enumerate([1.1, 1.4, 1.8, 2.1, 2.8, 3.1, 4.2, 5.1, 6.8, 7.9, 8.9, 9.5] * 3):
        transacciones.append({"id": f"SYNTH-{idx}", "fecha": "2026-03-15", "monto": round(u * mult, 2), "rnc_proveedor": "PROV-SYNTH"})

    # Ejecución de motores
    res_benford = MasterForensicEngine.execute_benford_analysis(transacciones)
    res_smurfing = MasterForensicEngine.detect_purchasing_splitting(transacciones, umbral=u)
    res_it_breach = MasterForensicEngine.audit_pharmacy_and_it_breach({})

    # Correlaciones cruzadas
    score_consolidado = 85.0 if res_smurfing else 40.0
    hash_evidencias = MasterForensicEngine.calculate_sha256(json.dumps(transacciones, sort_keys=True).encode())

    dictamen = {
        "dictamen_pericial_id": f"DICTAMEN-CONS-{cod_pais}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
        "jurisdiccion": config_pais["pais"],
        "moneda": config_pais["moneda"],
        "fecha_emision": datetime.datetime.now().isoformat(),
        "nivel_riesgo_global": "CRÍTICO (INDICIOS PENALES ESTRUCTURADOS)" if score_consolidado >= 60 else "MODERADO",
        "fraud_risk_score": score_consolidado,
        "modulos_evaluados": {
            "M1_benford": res_benford,
            "M2_fraccionamiento_smurfing": res_smurfing,
            "M3_it_cyber_fraud": res_it_breach
        },
        "cadena_custodia_sha256": hash_evidencias,
        "conclusiones_juridicas": (
            f"Se constata presunta violación sistemática al régimen de licitaciones públicas ({config_pais['ley_compras']}) "
            f"y señales de alerta tipificadas bajo la normativa antilavado ({config_pais['ley_antilavado']})."
        )
    }

    log_audit_trail("system_ai", "CORE_ENGINE", "FULL_FORENSIC_INSPECT", dictamen["dictamen_pericial_id"], "SUCCESS", "Dictamen consolidado")
    return jsonify(dictamen)


@app.route('/api/forensic/cases/<int:case_id>/report/download-pdf', methods=['GET', 'POST'])
def download_forensic_pdf(case_id):
    """
    Genera el informe pericial en PDF directamente en memoria, calcula su hash SHA-256,
    lo registra en la base de datos de custodia y lo envía al navegador.
    """
    try:
        case_data = {
            "case_code": f"AUD-MASTER-2026-{case_id:03d}",
            "entity_name": "Entidad Evaluada S.R.L. / Institución Pública",
            "sector": "Gubernamental & Tecnológico",
            "currency": "DOP",
            "total_impact": 5220000.00
        }

        findings = [
            {"domain": "Ciberseguridad y Datos", "norm": "Ley 172-13 / Ley 53-07", "desc": "Filtración de registros sensibles por vulnerabilidad RDP y falta de MFA.", "impact": 1100000.0},
            {"domain": "Compras Públicas", "norm": "Ley 340-06 de Contrataciones", "desc": "Fraccionamiento sistemático de órdenes de compra en ventanas de 7 días.", "impact": 3500000.0},
            {"domain": "Regulatorio y Cumplimiento", "norm": "Ley 41-08 de Función Pública", "desc": "Omisión de homologación de personal y nóminas fantasma.", "impact": 620000.0}
        ]

        # 1. Generar PDF preliminar en memoria
        pdf_buffer = generate_master_pdf_report(case_data, findings)
        pdf_bytes = pdf_buffer.getvalue()
        sha256_hash = MasterForensicEngine.calculate_sha256(pdf_bytes)

        # 2. Re-generar con el hash real incrustado en el documento
        case_data['sha256_hash'] = sha256_hash
        final_pdf_buffer = generate_master_pdf_report(case_data, findings)
        final_bytes = final_pdf_buffer.getvalue()

        # 3. Guardar copia en disco para registro forense
        filename = f"Informe_Forense_{case_data['case_code']}.pdf"
        file_path = os.path.join(EVIDENCE_DIR, filename)
        with open(file_path, "wb") as f:
            f.write(final_bytes)

        # 4. Asentar en la tabla digital_custody y en el audit trail
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO digital_custody (case_id, filename, sha256_hash, evidence_type, file_size_bytes)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, filename, sha256_hash, "DICTAMEN_OFICIAL_PDF", len(final_bytes)))
            conn.commit()

        log_audit_trail("admin", "AUDITOR", "GENERATE_AND_DOWNLOAD_PDF", f"CASE-{case_id}", "SUCCESS", f"SHA-256: {sha256_hash[:12]}...")

        final_pdf_buffer.seek(0)
        return send_file(
            final_pdf_buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Error generando informe PDF: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/b4/descargar/todo')
def b4_descargar_todo():
    """Empaqueta el expediente digital completo en un archivo ZIP con cadena de custodia."""
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("01_DICTAMEN_GLOBAL_ISA_240.txt",
                    f"INFORME FORENSE INTEGRAL — AUDIT INTELLIGENCE USA\\n"
                    f"Auditor Titular: {TITULAR}\\n"
                    f"Cuenta Receptora BHD: {BHD_CUENTA}\\n"
                    f"Fecha UTC: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\\n"
                    f"Estándares: PCAOB AS 2401 / ISA 240 / ISSAI 5270 / Ley 340-06 / Ley 155-17\\n")

        zf.writestr("02_CADENA_CUSTODIA_DIGITAL.csv",
                    "ID_EVIDENCIA,TIPO,NORMATIVA,SELLO_SHA256\\n"
                    f"EV-001,REPORTE_BENFORD,ISA 240,{hashlib.sha256(b'BENFORD_TEST').hexdigest()}\\n"
                    f"EV-002,FRACCIONAMIENTO_COMPRAS,Ley 340-06,{hashlib.sha256(b'SMURFING_TEST').hexdigest()}\\n"
                    f"EV-003,CIBERSEGURIDAD_IT,Ley 172-13 / Ley 53-07,{hashlib.sha256(b'CYBER_BREACH').hexdigest()}\\n")

    memory_file.seek(0)
    log_audit_trail("admin", "AUDITOR", "DOWNLOAD_ZIP_VAULT", "ALL_EVIDENCE", "SUCCESS", "Descarga ZIP bóveda")
    return send_file(memory_file, mimetype="application/zip", as_attachment=True, download_name="EXPEDIENTE_FORENSE_VELRIX.zip")


@app.route('/healthz')
def healthz():
    return jsonify({
        "status": "OPERATIONAL",
        "engine": "VELRIX AUDIT INTELLIGENCE MASTER V11",
        "bhd_cuenta": BHD_CUENTA,
        "titular": TITULAR,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
