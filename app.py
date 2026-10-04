# app.py v7.0 FINAL - PEDRO BALDERA - BHD 08694150021
# CONTACTO: licpedrobaldera@gmail.com - 18297717390
import os, json, jwt, datetime, glob, requests
import pandas as pd, duckdb
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import chromadb
from chromadb.utils import embedding_functions
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv("SECRET","BHD_08694150021_Pedro_2026")

# === DATOS REALES PEDRO BALDERA ===
BHD_CUENTA = "08694150021"
BHD_TITULAR = "Pedro Baldera"
BHD_BANCO = "BHD León"
EMAIL_ADMIN = "licpedrobaldera@gmail.com"
WHATSAPP_ADMIN = "18297717390" # Su número real
WEBSITE = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQJhfqoLvN9Pf4535A-yvlC0Bcc6zbYGVCUnIYvebLgMzsH6gOtpnD33l0&s"
WHATSAPP_TOKEN = os.getenv("WHATSAPP_TOKEN","")
WHATSAPP_PHONE_ID = os.getenv("WHATSAPP_PHONE_ID","")

DATA_LAKE = "./data"
os.makedirs(DATA_LAKE, exist_ok=True)
os.makedirs("./storage/comprobantes", exist_ok=True)

con = duckdb.connect(':memory:')
chroma_client = chromadb.PersistentClient(path="./storage/chroma")
collection = chroma_client.get_or_create_collection("auditoria_bhd", embedding_function=embedding_functions.DefaultEmbeddingFunction())

CLIENTES_DB = "./storage/clientes.json"
if not os.path.exists(CLIENTES_DB): json.dump({}, open(CLIENTES_DB,'w'))
def get_clientes():
    try: return json.load(open(CLIENTES_DB))
    except: return {}
def save_clientes(d): json.dump(d, open(CLIENTES_DB,'w'), indent=2)

def enviar_whatsapp_admin(mensaje):
    try:
        if WHATSAPP_TOKEN and WHATSAPP_PHONE_ID:
            url = f"https://graph.facebook.com/v19.0/{WHATSAPP_PHONE_ID}/messages"
            headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type": "application/json"}
            data = {"messaging_product":"whatsapp","to":WHATSAPP_ADMIN,"type":"text","text":{"body":mensaje}}
            requests.post(url, headers=headers, json=data, timeout=10)
        print(f"\n=== WHATSAPP PARA {BHD_TITULAR} {WHATSAPP_ADMIN} ===\n{mensaje}\n")
        return True
    except Exception as e:
        print(e); return False

def crear_token(email, plan="free"):
    payload={"email":email,"plan":plan,"exp":datetime.datetime.utcnow()+datetime.timedelta(days=30)}
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
def verificar_token(t):
    try: return jwt.decode(t, app.config['SECRET_KEY'], algorithms=["HS256"])
    except: return None

@app.route("/api/auth/register", methods=["POST"])
def register():
    d=request.get_json(); clientes=get_clientes()
    if d['email'] in clientes: return jsonify({"error":"Ya existe"}),400
    clientes[d['email']]={"password":d['password'],"empresa":d.get('empresa',''),"plan":"free","creado":str(datetime.datetime.now())}
    save_clientes(clientes)
    return jsonify({"token":crear_token(d['email'],"free"),"email":d['email'],"plan":"free"})

@app.route("/api/auth/login", methods=["POST"])
def login():
    d=request.get_json(); clientes=get_clientes(); c=clientes.get(d['email'])
    if not c or c['password']!=d['password']: return jsonify({"error":"Credenciales malas"}),401
    return jsonify({"token":crear_token(d['email'],c['plan']),"plan":c['plan'],"email":d['email']})

@app.route("/api/pago/bhd_info", methods=["GET"])
def bhd_info():
    return jsonify({
        "banco":BHD_BANCO, "cuenta":BHD_CUENTA, "titular":BHD_TITULAR, "moneda":"RD$",
        "email":EMAIL_ADMIN, "whatsapp":WHATSAPP_ADMIN, "web":WEBSITE,
        "precios":{"BASIC":7500,"PRO":30000,"ENTERPRISE":75000}
    })

@app.route("/api/pago/subir_comprobante", methods=["POST"])
def subir_comprobante():
    token=request.headers.get('Authorization','').replace('Bearer ','')
    user=verificar_token(token)
    if not user: return jsonify({"error":"Login requerido"}),401
    file=request.files.get('comprobante'); plan=request.form.get('plan','PRO')
    if not file: return jsonify({"error":"Suba foto comprobante BHD"}),400
    filename=f"./storage/comprobantes/{user['email']}_{plan}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    file.save(filename)
    clientes=get_clientes()
    if user['email'] in clientes:
        clientes[user['email']]['pago_pendiente']={"plan":plan,"comprobante":filename,"fecha":str(datetime.datetime.now()),"monto":30000 if plan=="PRO" else 7500,"cuenta":f"{BHD_BANCO} {BHD_CUENTA} - {BHD_TITULAR}","estado":"pendiente"}
        save_clientes(clientes)
    mensaje=f"💰 NUEVO PAGO BHD {BHD_CUENTA}!\n\nCliente: {user['email']}\nPlan: {plan}\nMonto: RD$ {30000 if plan=='PRO' else 7500}\nCuenta: {BHD_BANCO} {BHD_CUENTA} - {BHD_TITULAR}\n\nContacto admin: {EMAIL_ADMIN} - {WHATSAPP_ADMIN}\n\nComprobante: {filename}\nActive en /api/admin/pendientes"
    enviar_whatsapp_admin(mensaje)
    return jsonify({"status":"recibido","msg":f"Gracias. Verificaremos su pago a BHD {BHD_CUENTA} y le avisaremos a {EMAIL_ADMIN}. Notificado a {WHATSAPP_ADMIN}."})

def generar_factura_bhd(email_cliente, plan, monto):
    fecha=datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    num_factura=f"BHD-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
    filename=f"./storage/comprobantes/FACTURA_{num_factura}_{email_cliente}.pdf"
    c=canvas.Canvas(filename, pagesize=letter); width,height=letter
    c.setFillColor(colors.HexColor("#00A859")); c.rect(0,height-80,width,80,fill=1,stroke=0)
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold",18); c.drawString(30,height-50,"AUDIT INTELLIGENCE v7.0")
    c.setFont("Helvetica",9); c.drawString(30,height-65,f"FACTURA: {num_factura} | BHD {BHD_CUENTA} - {BHD_TITULAR} | {EMAIL_ADMIN}")
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold",11); c.drawString(30,height-110,"EMISOR:")
    c.setFont("Helvetica",9)
    c.drawString(30,height-125,f"Titular: {BHD_TITULAR} - {EMAIL_ADMIN}"); c.drawString(30,height-138,f"Banco: {BHD_BANCO} - Cuenta: {BHD_CUENTA} Ahorros RD$")
    c.drawString(30,height-151,f"WhatsApp: +{WHATSAPP_ADMIN} - Los Frailes, SDE")
    c.drawString(30,height-164,f"Web: {WEBSITE[:60]}")
    c.setFont("Helvetica-Bold",11); c.drawString(320,height-110,"CLIENTE:")
    c.setFont("Helvetica",9); c.drawString(320,height-125,f"Email: {email_cliente}"); c.drawString(320,height-138,f"Fecha: {fecha}"); c.drawString(320,height-151,f"Plan: {plan.upper()} - RD$ {monto}")
    y=height-220; c.setFillColor(colors.HexColor("#f0f0f0")); c.rect(30,y-10,width-60,25,fill=1,stroke=0)
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold",10); c.drawString(35,y,"DESCRIPCION"); c.drawString(400,y,"MONTO")
    y-=30; c.setFont("Helvetica",10); c.drawString(35,y,f"Suscripcion {plan.upper()} - 30 dias ilimitado"); c.drawString(400,y,f"RD$ {monto:,.2f}")
    y-=80; c.setFillColor(colors.HexColor("#00A859")); c.rect(300,y-10,width-330,30,fill=1,stroke=0)
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold",13); c.drawString(310,y,f"TOTAL: RD$ {monto:,.2f}")
    c.setFillColor(colors.black); c.setFont("Helvetica",8); c.drawString(30,80,f"Pago verificado a BHD {BHD_CUENTA} - {BHD_TITULAR}. Contacto {EMAIL_ADMIN} / +{WHATSAPP_ADMIN}")
    c.setFont("Helvetica-Bold",9); c.setFillColor(colors.HexColor("#00A859")); c.drawString(30,40,f"✓ PAGO VERIFICADO BHD {BHD_CUENTA} - ACTIVO")
    c.save(); return filename

@app.route("/api/admin/pendientes", methods=["GET"])
def pendientes():
    clientes=get_clientes(); pend={k:v for k,v in clientes.items() if 'pago_pendiente' in v and v['pago_pendiente']['estado']=='pendiente'}
    return jsonify(pend)

@app.route("/api/admin/activar/<email>", methods=["POST"])
def activar(email):
    clientes=get_clientes()
    if email not in clientes: return jsonify({"error":"No existe"}),404
    plan_data=clientes[email].get('pago_pendiente',{}); nuevo_plan=plan_data.get('plan','PRO').lower(); monto=plan_data.get('monto',30000)
    clientes[email]['plan']=nuevo_plan; clientes[email]['pago_pendiente']['estado']='verificado'; clientes[email]['activado_por']=f"{BHD_TITULAR} - {BHD_CUENTA} - {EMAIL_ADMIN}"; clientes[email]['activado_fecha']=str(datetime.datetime.now()); save_clientes(clientes)
    factura_path=generar_factura_bhd(email,nuevo_plan,monto)
    enviar_whatsapp_admin(f"✅ ACTIVADO + FACTURA:\n{email}\nPlan {nuevo_plan.upper()} RD${monto}\nFactura {factura_path}\nBHD {BHD_CUENTA}")
    return jsonify({"status":"ACTIVADO","email":email,"plan":nuevo_plan,"factura":factura_path,"admin":EMAIL_ADMIN,"whatsapp":WHATSAPP_ADMIN})

@app.route("/")
def home(): return jsonify({"SAAS":f"AUDIT v7.0 - BHD {BHD_CUENTA} - {BHD_TITULAR}","email":EMAIL_ADMIN,"whatsapp":WHATSAPP_ADMIN,"web":WEBSITE,"status":"24/7"})

if __name__=="__main__":
    app.run(host="0.0.0.0", port=5000)
