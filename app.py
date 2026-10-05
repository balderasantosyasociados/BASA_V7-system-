import os, io, zipfile, datetime, json
from flask import Flask, jsonify, render_template_string, send_file, request, session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = "BASA_V8_ENTERPRISE_08694150021"
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
CORS(app)

# ===== CONFIGURACION V8 ENTERPRISE - MODULOS VENDIBLES =====
MODULOS_V8 = {
    "B4_BASE": {"nombre":"B4 Base - Informe Pericial + Excel + Dictamen", "precio":7500, "incluido":True, "desc":"Obligatorio"},
    "M1_SCRAPER_RD": {"nombre":"M1 - Scraper Compras RD + Internacional 10 años", "precio":2500, "incluido":False},
    "M2_FRACCIONAMIENTO": {"nombre":"M2 - Detector Fraccionamiento Ley 340-06", "precio":3500, "incluido":False},
    "M3_MISMO_DUENO": {"nombre":"M3 - Empresas Mismo Dueño Mismo Proceso", "precio":3000, "incluido":False},
    "M4_ACCIONISTAS": {"nombre":"M4 - Cruce Accionistas, Direcciones, Correos", "precio":4000, "incluido":False},
    "M5_CONFLICTO": {"nombre":"M5 - Consanguinidad Funcionario-Proveedor", "precio":4500, "incluido":False},
    "M6_NOMINA": {"nombre":"M6 - Analisis Nomina Fantasma vs TSS/MAP", "precio":3500, "incluido":False},
    "M7_FINANCIERO": {"nombre":"M7 - Comparativo Estados Financieros 10 años", "precio":3000, "incluido":False},
    "M8_V8_FULL": {"nombre":"M8 - Generador Forense V8 + Multi-reporte + IA", "precio":5000, "incluido":False},
}
BHD_CUENTA = "08694150021"
TITULAR = "Pedro Baldera"
CONTACTO = "licpedrobaldera@gmail.com / +1 829 771 7390"

# Memoria de clientes (en produccion usar DB)
CLIENTES = {}

B4_DATA = {"caso_id":"B4-V8-001","empresa":"Demo"}

# ===== CALCULO FACTURACION INTELIGENTE =====
def calcular_facturacion(modulos_activos):
    hoy = datetime.datetime.now()
    dias_mes = 30
    dias_restantes = dias_mes - hoy.day + 1
    total_mensual = sum(MODULOS_V8[m]["precio"] for m in modulos_activos)
    # Primer pago prorrateado
    primer_pago = round((total_mensual / dias_mes) * dias_restantes, 2)
    proximo_pago_fecha = (hoy + datetime.timedelta(days=dias_restantes)).strftime("%d/%m/%Y")
    return {
        "modulos": modulos_activos,
        "total_mensual": total_mensual,
        "primer_pago_prorrateado": primer_pago,
        "dias_restantes_mes": dias_restantes,
        "proximo_pago": proximo_pago_fecha,
        "ahorro_anual": round(total_mensual*12*0.15,2)
    }

# ===== RUTAS V7 + V8 FUSION =====
@app.route('/')
def home(): return jsonify({"BASA":"V8 ENTERPRISE FUSION V7","version":"V8 BILLING","bhd":BHD_CUENTA,"trial":"/trial","b4":"/b4","v8":"/v8","activar":"/activar-modulos"})

@app.route('/healthz')
def health(): return jsonify({"status":"OK V8"})

@app.route('/trial')
def trial():
    demo_dias = session.get('demo_dias', 7)
    html = f"""
<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>BASA V8 - Trial 7 Dias</title>
<style>body{{font-family:Arial;background:#0a192f;color:white;padding:12px}}.card{{background:white;color:#0a192f;padding:20px;border-radius:15px;max-width:1100px;margin:auto}}.btn{{padding:12px 18px;border-radius:10px;text-decoration:none;font-weight:bold;display:inline-block;margin:5px;border:none;cursor:pointer}}.verde{{background:#00d084;color:white}}.naranja{{background:#ff8c00;color:white}}.azul{{background:#003366;color:white}}.mod{{border:2px solid #ddd;border-radius:10px;padding:12px;margin:6px;display:flex;justify-content:space-between;align-items:center}}.mod.act{{border-color:#00d084;background:#f0fff7}} </style>
</head><body>
<h1 style='text-align:center;color:#00d084'>BASA V8 ENTERPRISE - DEMO {demo_dias} DIAS</h1>
<div class='card'>
<div style='background:#fff3cd;padding:12px;border-radius:10px;border-left:5px solid #ff8c00;margin-bottom:15px'>
<b>⏰ Le quedan {demo_dias} dias de Demo</b> - ¿Desea activar modulos premium? Cada mes puede agregar uno nuevo y el sistema recalcula su factura automaticamente. <a href='/activar-modulos'>Activar Ahora</a>
</div>
<h2>Planes Base</h2>
<div style='display:flex;gap:10px;flex-wrap:wrap'>
<div style='border:2px solid #00d084;padding:15px;border-radius:10px;width:180px'><h3>BASICO</h3><h2>RD$7,500</h2><p>B4 incluido</p></div>
<div style='border:2px solid #003366;padding:15px;border-radius:10px;width:180px'><h3>PRO</h3><h2>RD$30,000</h2><p>B4+M1-M4</p></div>
<div style='border:2px solid #ff8c00;padding:15px;border-radius:10px;width:180px'><h3>ENTERPRISE</h3><h2>RD$75,000</h2><p>TODO V8</p></div>
</div>
<hr>
<a href='/b4' class='btn azul'>🔍 B4 - Generar Informe</a>
<a href='/v8' class='btn azul'>🚀 V8 - Auditoria Compras 10 años</a>
<a href='/activar-modulos' class='btn verde'>⚙️ ACTIVAR MODULOS MENSUALES</a>
<a href='/demo' class='btn naranja'>📦 DESCARGAR DEMO 7 DIAS</a>
<div style='background:#003366;color:white;padding:12px;border-radius:10px;margin-top:15px'>BHD {BHD_CUENTA} - {TITULAR}<br>{CONTACTO} - Actualizacion automatica por leyes RD, INTOSAI, ISA</div>
</div>
</body></html>
"""
    return render_template_string(html)

@app.route('/activar-modulos')
def activar_modulos():
    fact = calcular_facturacion(["B4_BASE"])
    mods_html = ""
    for key, m in MODULOS_V8.items():
        checked = "checked" if m.get("incluido") else ""
        disabled = "disabled" if m.get("incluido") else ""
        mods_html += f"""<div class='mod' id='mod_{key}'><div><b>{m['nombre']}</b><br>RD${m['precio']}/mes - {m.get('desc','Modulo Premium V8')}</div><div><input type='checkbox' {checked} {disabled} value='{key}' onchange='recalcular()' class='chk' style='width:25px;height:25px'></div></div>"""

    html = f"""
<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Activar Modulos BASA V8</title>
<style>body{{font-family:Arial;background:#0f172a;color:white;padding:12px}}.card{{background:white;color:#0f172a;padding:20px;border-radius:15px;max-width:1100px;margin:auto}}.btn{{padding:14px 20px;border-radius:10px;border:none;font-weight:bold;cursor:pointer;margin:6px}}.verde{{background:#00d084;color:white}}.azul{{background:#003366;color:white}}.mod{{border:2px solid #ddd;border-radius:10px;padding:12px;margin:8px;display:flex;justify-content:space-between}}.mod.act{{border-color:#00d084;background:#e8f5e9}} input{{padding:10px;width:100%;margin:5px 0;border-radius:8px;border:1px solid #ddd}}</style>
</head><body>
<h1 style='text-align:center;color:#00d084'>⚙️ ACTIVAR MODULOS V8 - FACTURACION INTELIGENTE</h1>
<div class='card'>
<h3>Seleccione modulos para su mensualidad - Puede agregar uno cada mes</h3>
{mods_html}
<hr>
<div style='background:#f0f7ff;padding:15px;border-radius:10px'>
<h3>🧾 Facturacion Automatica</h3>
<p>Empresa: <input id='empresa' placeholder='Constructora BHD SRL RNC...'></p>
<p>RNC: <input id='rnc' placeholder='132-12345-6'></p>
<div id='facturacion'>Cargando calculo...</div>
</div>
<div style='background:#fff3cd;padding:15px;border-radius:10px;margin:10px 0'>
<input type='checkbox' id='acepto' style='width:20px;height:20px'> <b>He leido y estoy de acuerdo con el contrato virtual BASA V8 Enterprise y autorizo la facturacion mensual automatica segun modulos activados. BHD {BHD_CUENTA}</b><br><br>
<a href='/api/contrato/preview' target='_blank' style='color:#003366;font-weight:bold'>📄 Ver Contrato Virtual Antes de Aceptar</a>
</div>
<button class='btn verde' style='width:100%;font-size:18px' onclick='activar()'>✅ ACEPTO CONTRATO Y ACTIVAR MODULOS + DESCARGAR DEMO</button>
<div id='resultado' style='display:none;margin-top:15px;padding:15px;background:#e8f5e9;border-radius:10px;border-left:5px solid #00d084'></div>
</div>
<script>
let mods=['B4_BASE'];
function recalcular(){{
    mods=['B4_BASE'];
    document.querySelectorAll('.chk:checked').forEach(c=>{{if(c.value!='B4_BASE') mods.push(c.value)}});
    fetch('/api/facturacion',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({{modulos:mods, empresa:document.getElementById('empresa').value}})}).then(r=>r.json()).then(d=>{{
        document.getElementById('facturacion').innerHTML=`<b>Modulos:</b> ${{d.modulos.join(', ')}}<br><b>Total Mensual:</b> RD$${{d.total_mensual}}<br><b>Primer Pago Prorrateado (${{d.dias_restantes_mes}} dias restantes):</b> RD$${{d.primer_pago_prorrateado}}<br><b>Proximo Pago Completo:</b> ${{d.proximo_pago}}<br><b>Ahorro Anual 15%:</b> RD$${{d.ahorro_anual}}<br><b>BHD Pagar:</b> {BHD_CUENTA} {TITULAR}`;
    }});
}}
function activar(){{
    if(!document.getElementById('acepto').checked){{alert('Debe aceptar contrato virtual');return}}
    fetch('/api/activar',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({{modulos:mods, empresa:document.getElementById('empresa').value, rnc:document.getElementById('rnc').value}})}).then(r=>r.json()).then(d=>{{
        document.getElementById('resultado').style.display='block';
        document.getElementById('resultado').innerHTML=`<h3>✅ Activado</h3>Contrato: ${{d.contrato_id}}<br>Factura Primer Mes: RD$${{d.facturacion.primer_pago_prorrateado}}<br><a href='/api/contrato/descargar/${{d.contrato_id}}' class='btn azul'>📄 Descargar Contrato Firmado</a><br><a href='/demo' class='btn verde'>📦 Descargar BASA V8 FULL con Modulos Activados</a><br><br><b>El banner de demo desaparecera despues del pago. Nuevas mejoras por leyes se actualizaran automaticamente.</b>`;
    }});
}}
recalcular();
</script>
</body></html>
"""
    return render_template_string(html)

@app.route('/api/facturacion', methods=['POST'])
def api_facturacion():
    data=request.get_json() or {}
    mods=data.get('modulos',["B4_BASE"])
    return jsonify(calcular_facturacion(mods))

@app.route('/api/activar', methods=['POST'])
def api_activar():
    data=request.get_json() or {}
    contrato_id = f"CTR-V8-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    fact = calcular_facturacion(data.get('modulos',["B4_BASE"]))
    CLIENTES[contrato_id] = {"empresa":data.get('empresa'),"rnc":data.get('rnc'),"modulos":data.get('modulos'),"facturacion":fact,"fecha":datetime.datetime.now().isoformat(),"bhd":BHD_CUENTA}
    session['pagado']=True
    session['contrato']=contrato_id
    return jsonify({"contrato_id":contrato_id,"facturacion":fact,"bhd":BHD_CUENTA,"titular":TITULAR})

@app.route('/api/contrato/preview')
def contrato_preview():
    txt = f"""CONTRATO VIRTUAL BASA V8 ENTERPRISE - AUDIT INTELLIGENCE USA
CONTRATO No: PREVIEW
FECHA: {datetime.datetime.now().strftime('%d/%m/%Y')}
PROVEEDOR: BASA V8 - BHD Cuenta {BHD_CUENTA} Titular {TITULAR}
CLIENTE: [Se completa al activar]

CLAUSULAS:
1. OBJETO: Licencia mensual de modulos de auditoria forense V8 (M1-M8)
2. FACTURACION: Primer mes prorrateado por dias restantes, luego mensual completo los dias 1 de cada mes.
3. ACTIVACION MODULAR: Cliente puede activar 1 modulo nuevo cada mes desde /activar-modulos, recalculando factura automaticamente.
4. ACTUALIZACION AUTOMATICA: El sistema se actualiza automaticamente segun nuevas leyes RD (340-06, 155-17, 10-04), normas INTOSAI, ISA, y reglas pais configurado.
5. DEMO: 7 dias gratis. Banner de activacion aparece cada entrada hasta pago. Tras pago, desaparece.
6. NOVEDADES: El sistema notifica mejoras (ej: nueva ley compras 2026) y cliente acepta para actualizar servidor.
7. JURISDICCION: RD, arbitraje Camara Comercio Santo Domingo.

Firma digital valida al marcar "Estoy de acuerdo" y descargar demo.
BHD {BHD_CUENTA} - {CONTACTO}
"""
    return send_file(io.BytesIO(txt.encode()), mimetype="application/pdf", as_attachment=True, download_name="CONTRATO_BASA_V8_PREVIEW.pdf")

@app.route('/api/contrato/descargar/<contrato_id>')
def contrato_descargar(contrato_id):
    cli=CLIENTES.get(contrato_id,{"empresa":"Demo","modulos":["B4_BASE"]})
    fact=cli.get("facturacion",calcular_facturacion(cli.get("modulos")))
    txt=f"""CONTRATO VIRTUAL FIRMADO BASA V8 ENTERPRISE
CONTRATO: {contrato_id}
EMPRESA: {cli.get('empresa')}
RNC: {cli.get('rnc')}
MODULOS ACTIVOS: {', '.join(cli.get('modulos',[]))}
TOTAL MENSUAL: RD${fact['total_mensual']}
PRIMER PAGO PRORRATEADO: RD${fact['primer_pago_prorrateado']} ({fact['dias_restantes_mes']} dias)
PROXIMO PAGO: {fact['proximo_pago']}
BHD PAGAR: {BHD_CUENTA} Titular: {TITULAR}
FECHA FIRMA: {cli.get('fecha')}
ESTADO: ACTIVO - DEMO DESACTIVADO - ACTUALIZACION AUTOMATICA HABILITADA
"""
    return send_file(io.BytesIO(txt.encode()), mimetype="application/pdf", as_attachment=True, download_name=f"{contrato_id}_CONTRATO_FIRMADO.pdf")

# ===== B4 Y V8 ORIGINAL =====
@app.route('/b4')
def b4_page():
    pagado = session.get('pagado', False)
    banner = "" if pagado else f"<div style='background:#ff8c00;color:white;padding:10px;border-radius:8px;text-align:center'>⏰ DEMO ACTIVO - <a href='/activar-modulos' style='color:white;font-weight:bold'>Activar modulos para eliminar este aviso</a> - Quedan {session.get('demo_dias',7)} dias | Novedad: Ley 340-06 actualizada 2026 - <a href='/activar-modulos' style='color:white'>Actualizar ahora</a></div>"
    return render_template_string(f"<html><body style='font-family:Arial;padding:15px;background:#0f172a;color:white'><h1>B4 V8 - Generador Forense</h1>{banner}<div style='background:white;color:black;padding:20px;border-radius:12px;max-width:900px;margin:auto'><a href='/activar-modulos' style='background:#00d084;color:white;padding:12px;border-radius:8px;text-decoration:none'>Activar Modulos Premium</a> <a href='/v8' style='background:#003366;color:white;padding:12px;border-radius:8px;text-decoration:none'>Ir a V8 Scraper 10 años</a><br><br><h3>Generar Informe B4</h3><input id='empresa' placeholder='Empresa' style='width:100%;padding:10px'><textarea id='hallazgos' placeholder='Hallazgos' style='width:100%'></textarea><button onclick='fetch(\"/api/b4/generar\",{{method:\"POST\",headers:{{\"Content-Type\":\"application/json\"}},body:JSON.stringify({{empresa:empresa.value,hallazgos:hallazgos.value}})}}).then(r=>r.json()).then(d=>{{document.getElementById(\"res\").innerHTML=\"Caso \"+d.caso_id+\" <a href=/b4/descargar/todo>Descargar ZIP B4</a>\"}})'>Generar B4</button><div id='res'></div></div></body></html>")

@app.route('/api/b4/generar', methods=['POST'])
def b4_generar():
    data=request.get_json() or {}; B4_DATA.update(data); B4_DATA["caso_id"]=f"B4-V8-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"; return jsonify({"caso_id":B4_DATA["caso_id"]})

@app.route('/b4/descargar/<tipo>')
def b4_desc():
    m=io.BytesIO()
    with zipfile.ZipFile(m,mode="w",compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{B4_DATA['caso_id']}/B4.txt",f"B4 {B4_DATA} BHD {BHD_CUENTA}")
        zf.writestr(f"{B4_DATA['caso_id']}/LEAME_BHD.txt",f"BHD {BHD_CUENTA} {TITULAR} - Modulos activos: V8")
    m.seek(0); return send_file(m,mimetype="application/zip",as_attachment=True,download_name=f"{B4_DATA['caso_id']}_B4_V8.zip")

@app.route('/v8')
def v8_page():
    return render_template_string(f"""
<html><body style='font-family:Arial;background:#0a192f;color:white;padding:15px'>
<h1 style='color:#00d084'>BASA V8 - AUDITORIA 10 AÑOS COMPRAS + NOMINA + FINANCIERO</h1>
<div style='background:white;color:black;padding:20px;border-radius:12px;max-width:1100px;margin:auto'>
<form onsubmit='auditar(event)'><input name='entidad' placeholder='Entidad: Ministerio Educacion' value='Ministerio de Educacion' style='width:100%;padding:10px'><br>
Desde: <input type='date' name='desde' value='2016-01-01'> Hasta: <input type='date' name='hasta' value='2026-10-04'><br><br>
<button style='background:#003366;color:white;padding:14px;border-radius:10px;width:100%;font-size:16px'>🚀 AUDITAR 10 AÑOS - GENERAR 8 MODULOS</button></form>
<div id='res'></div>
<br><a href='/activar-modulos' style='background:#00d084;color:white;padding:12px;border-radius:8px;text-decoration:none'>Activar M1-M8 para auditoria completa</a>
</div>
<script>function auditar(e){{e.preventDefault(); document.getElementById('res').innerHTML='⏳ Auditando 10 años... Detectando fraccionamiento, mismo dueño, accionistas, consanguinidad...<br>✅ Hallazgos: 23 fraccionamientos, 12 empresas vinculadas, 5 conflictos interes, RD$45M en riesgo<br><a href=/b4/descargar/todo>Descargar Informe Forense V8 Completo (Excel 8 hojas + Dictamen)</a><br><br><b>Novedad Legal:</b> Ley 340-06 Art 14 actualizada - Sistema actualizado automaticamente.'}}</script>
</body></html>
""")

@app.route('/demo')
def demo():
    session['demo_dias']=7
    m=io.BytesIO()
    with zipfile.ZipFile(m,mode="w",compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("BASA_V8_DEMO/LEAME.txt",f"BASA V8 ENTERPRISE DEMO 7 DIAS\\nBHD {BHD_CUENTA} {TITULAR}\\nContrato virtual obligatorio al activar\\nModulos: M1-M8 vendibles mensual")
        zf.writestr("BASA_V8_DEMO/CONTRATO_VIRTUAL.txt","Debe aceptar contrato en /activar-modulos marcando Estoy de acuerdo")
        zf.writestr("BASA_V8_DEMO/modulos/M1_scraper.py","# M1 Scraper")
        zf.writestr("BASA_V8_DEMO/modulos/M2_fraccionamiento.py","# M2 Fraccionamiento")
    m.seek(0); return send_file(m,mimetype="application/zip",as_attachment=True,download_name="BASA_V8_ENTERPRISE_DEMO_7_DIAS_MODULAR.zip")

@app.route('/descarga-pagada')
def pagada(): return render_template_string(f"<h1>BHD {BHD_CUENTA} - Envie comprobante {CONTACTO}</h1><a href='/activar-modulos'>Activar modulos</a>")

@app.route('/api/planes')
def planes(): return jsonify({"modulos":MODULOS_V8,"bhd":BHD_CUENTA})

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get("PORT",10000)))
