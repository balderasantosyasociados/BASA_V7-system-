# app.py v7.0 FINAL - BALDERA SANTOS Y ASOCIADOS SRL - 03/10/2026
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os, jwt, datetime, json, glob, hashlib
import pandas as pd, duckdb
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import requests
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app, origins=["*"])
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "baldera_santos_v7_pro_2026_8297717390")
POLAR_ACCESS_TOKEN = os.getenv("POLAR_ACCESS_TOKEN", "")
POLAR_CHECKOUT = "https://buy.polar.sh/polar_cl_Ptbmj5cbqBoGoILeQIJz2E4XNySiLU1asyFb52YJ7fM"
CLIENTES_DB = "./clientes.json"
DATA_LAKE = "./data"
os.makedirs(DATA_LAKE, exist_ok=True)
if not os.path.exists(CLIENTES_DB):
    json.dump({}, open(CLIENTES_DB,'w'))

def get_clientes():
    try: return json.load(open(CLIENTES_DB))
    except: return {}
def save_clientes(d): json.dump(d, open(CLIENTES_DB,'w'), indent=2)
def crear_token(email, plan="free"):
    return jwt.encode({"email":email,"plan":plan,"exp":datetime.datetime.utcnow()+datetime.timedelta(days=30)}, app.config['SECRET_KEY'], algorithm="HS256")
def verificar_token(t):
    try: return jwt.decode(t, app.config['SECRET_KEY'], algorithms=["HS256"])
    except: return None

@app.route("/")
def home():
    return jsonify({"status":"AUDIT INTELLIGENCE USA v7.0 ACTIVO","polar":POLAR_CHECKOUT,"token_config": bool(POLAR_ACCESS_TOKEN),"clientes":len(get_clientes())})

@app.route("/api/salud")
def salud():
    return jsonify({"ok":True,"v":"7.0","msg":"Backend Baldera Santos corriendo 24/7","polar_token": "CONFIGURADO" if POLAR_ACCESS_TOKEN else "FALTA - MODO DEMO"})

@app.route("/api/auth/register", methods=["POST"])
def register():
    d=request.get_json(); email=d.get('email'); pwd=d.get('password')
    if not email or not pwd: return jsonify({"error":"Falta email/pass"}),400
    c=get_clientes()
    if email in c: return jsonify({"error":"Ya existe"}),400
    c[email]={"password":pwd,"empresa":d.get('empresa','Baldera Santos'),"plan":"free","creado":str(datetime.datetime.now())}
    save_clientes(c)
    token=crear_token(email,"free")
    return jsonify({"token":token,"email":email,"plan":"free"})

@app.route("/api/auth/login", methods=["POST"])
def login():
    d=request.get_json(); c=get_clientes().get(d.get('email'))
    if not c or c['password']!=d.get('password'): return jsonify({"error":"Credenciales"}),401
    token=crear_token(d.get('email'),c['plan'])
    return jsonify({"token":token,"plan":c['plan'],"email":d.get('email')})

@app.route("/api/polar/verify", methods=["POST"])
def polar_verify():
    d=request.get_json(); checkout_id=d.get('checkout_id'); email=d.get('email')
    print(f"VERIFY {checkout_id} {email}")
    if POLAR_ACCESS_TOKEN:
        try:
            headers={"Authorization": f"Bearer {POLAR_ACCESS_TOKEN}"}
            r=requests.get(f"https://api.polar.sh/v1/checkouts/{checkout_id}", headers=headers, timeout=10)
            if r.status_code==200:
                j=r.json()
                if j.get('status') in ['succeeded','paid','completed'] or 'paid' in str(j).lower():
                    clientes=get_clientes()
                    if email in clientes:
                        clientes[email]['plan']='pro'; clientes[email]['polar']=checkout_id
                        save_clientes(clientes)
                    return jsonify({"paid":True,"plan":"pro","real":True})
        except Exception as e:
            print(e)
    # MODO DEMO
    clientes=get_clientes()
    if email in clientes:
        clientes[email]['plan']='pro'; save_clientes(clientes)
    return jsonify({"paid":True,"plan":"pro","demo":True})

@app.route("/api/polar/webhook", methods=["POST"])
def webhook():
    print("WEBHOOK", request.get_json())
    return jsonify({"ok":True})

@app.route("/api/generar_pdf_contraloria", methods=["POST"])
def pdf():
    token=request.headers.get('Authorization','').replace('Bearer ','')
    user=verificar_token(token)
    if not user: return jsonify({"error":"No auth"}),401
    d=request.get_json(); hall=d.get('hallazgos','Informe demo')[:5000]
    path=f"./Informe_{user['email'].replace('@','_')}.pdf"
    c=canvas.Canvas(path, pagesize=letter); w,h=letter
    c.setFillColor(colors.HexColor("#0a2a5e")); c.rect(0,h-80,w,80,fill=1,stroke=0)
    c.setFillColor(colors.HexColor("#D4AF37")); c.setFont("Helvetica-Bold",14); c.drawString(40,h-45,f"INFORME AUDITORIA - Baldera Santos y Asociados SRL")
    c.setFillColor(colors.white); c.setFont("Helvetica",8); c.drawString(40,h-65,f"{user['email']} | {datetime.datetime.now()} | v7.0")
    t=c.beginText(40,h-110); t.setFont("Helvetica",9); t.setFillColor(colors.black)
    for line in hall.split('\n'):
        for ch in [line[i:i+100] for i in range(0,len(line),100)]: t.textLine(ch)
    c.drawText(t)
    c.setFont("Helvetica-Bold",7); c.drawString(40,30,f"Hash {hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:10]} | BHD 08694150021 | Los Frailes SDE | 829-771-7390")
    c.save()
    return send_file(path, as_attachment=True)

@app.route("/upload_infinito", methods=["POST"])
def upload():
    files=request.files.getlist('files'); tot=0
    for f in files:
        p=os.path.join(DATA_LAKE,f.filename); f.save(p)
        try:
            df=pd.read_csv(p) if p.endswith('.csv') else pd.read_excel(p)
            df.to_parquet(p.replace('.csv','.parquet').replace('.xlsx','.parquet')); tot+=1
        except: pass
    return jsonify({"total_parquet":len(glob.glob(DATA_LAKE+"/*.parquet")),"nuevos":tot})

@app.route("/investigar_lake", methods=["POST"])
def investigar():
    pregunta=request.form.get('pregunta','Analiza')
    try:
        con=duckdb.connect(); cnt=con.execute(f"SELECT COUNT(*) FROM read_parquet('{DATA_LAKE}/*.parquet')").fetchone()[0]
    except: cnt=0
    return jsonify({"meta_ai_hipotesis":f"Hipotesis para: {pregunta} - Buscar nomina fantasma","gemini_tecnico":f"Filas: {cnt}","sql_sugerido":f"SELECT * FROM read_parquet('{DATA_LAKE}/*.parquet') LIMIT 10"})

@app.route("/sql", methods=["POST"])
def sql():
    s=request.form.get('sql')
    try:
        df=duckdb.connect().execute(s).fetchdf()
        return jsonify({"data":df.head(200).to_dict(orient='records')})
    except Exception as e:
        return jsonify({"error":str(e)}),400

if __name__=="__main__":
    print(f"--- v7.0 CORRIENDO - Polar token: {'OK' if POLAR_ACCESS_TOKEN else 'MODO DEMO'} ---")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT",5000)), debug=True)
