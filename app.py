# -*- coding: utf-8 -*-
import os
import requests
import json
from flask import Flask, jsonify, request, Response, send_file
from flask_cors import CORS
import mysql.connector
from dotenv import load_dotenv
# ✨ REEMPLAZA la línea 'from datetime import datetime' CON ESTE BLOQUE COMPLETO ✨
from datetime import datetime, date, timedelta
from decimal import Decimal
import io
import re # Importado para la limpieza de números de teléfono

# --- NUEVAS IMPORTACIONES ---
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pandas as pd
from openai import OpenAI
import pytz
from drive_uploader import upload_file_to_drive
import re
import hashlib
from celery_tasks import send_whatsapp_notification_task
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, request, Response, send_file, send_from_directory, g
import jwt
import bcrypt
import logging
from logging.handlers import RotatingFileHandler
import traceback

# --- CONFIGURACIÓN INICIAL --- 
load_dotenv()
app = Flask(__name__)

app.config['SECRET_KEY'] = 'macarronconquesoysandia151123'

# --- CONFIGURACIÓN DE LOGGING ---
if not app.debug:
    # Configurar el handler de archivos rotativos
    file_handler = RotatingFileHandler('app.log', maxBytes=10*1024*1024, backupCount=3)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('CRM Backend startup')

github_pages_url = "https://henmir-hn.github.io/portal-empleo-henmir"

# Reemplaza la línea CORS(app) con este bloque
CORS(app, resources={r"/api/*": {"origins": "https://aethra-ai.github.io"}})
# También, para las rutas públicas, necesitas una configuración separada o una más general
# La siguiente configuración es más simple y debería funcionar para ambos casos:
# Descomenta esta y comenta la anterior si sigues teniendo problemas.
#
# CORS(app, origins=["http://127.0.0.1:5500", "https://henmir-hn.github.io"], 
#      methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"], 
#      allow_headers=["Content-Type", "Authorization", "X-API-Key"], 
#      supports_credentials=True)

openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
# AGREGA ESTE BLOQUE COMPLETO DESPUÉS DE LA LÍNEA 'openai_client = ...'

from functools import wraps # <<< ASEGÚRATE DE QUE ESTA IMPORTACIÓN ESTÉ ARRIBA CON LAS DEMÁS

# --- CONFIGURACIÓN DE SEGURIDAD PARA LA API DEL BOT ---
INTERNAL_API_KEY = os.getenv('INTERNAL_API_KEY')


@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Endpoint para autenticar usuarios. Recibe un email y contraseña,
    y si son válidos, devuelve un token JWT.
    """
    app.logger.info("--- INICIANDO PROCESO DE LOGIN ---")
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        app.logger.info(f"Intento de login para el email: [{email}]")
        
        if not email or not password:
            return jsonify({'message': 'Email y contraseña son requeridos'}), 401

        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Error de conexión a la base de datos"}), 500
        
        cursor = conn.cursor(dictionary=True)
        
        # --- CONSULTA CORREGIDA CON JOIN ---
        # Esta consulta une Users y Clientes para obtener el id_cliente del usuario
        app.logger.info("Buscando usuario y su id_cliente asociado...")
        cursor.execute("""
            SELECT u.id, u.email, u.password_hash, u.id_cliente 
            FROM Users u
            WHERE u.email = %s
        """, (email,))
        user = cursor.fetchone()

        if not user:
            app.logger.warning(f"LOGIN FALLIDO: Usuario no encontrado en la BD para el email [{email}].")
            return jsonify({'message': 'Credenciales inválidas'}), 401

        app.logger.info(f"Usuario encontrado. ID: {user['id']}, ID Cliente (Tenant): {user['id_cliente']}")
        
        password_from_db_hash = user['password_hash']
        password_bytes = password.encode('utf-8')
        hash_bytes = password_from_db_hash.encode('utf-8')
        
        if bcrypt.checkpw(password_bytes, hash_bytes):
            app.logger.info("¡ÉXITO! La contraseña coincide.")
            
            tenant_id = user.get('id_cliente')
            if not tenant_id:
                app.logger.error(f"Error Crítico: El usuario {email} no tiene un id_cliente (tenant_id) asociado.")
                return jsonify({'message': 'Error de configuración de cuenta'}), 500

            # --- CREACIÓN DEL TOKEN CORRECTA ---
            token = jwt.encode({
                'user_id': user['id'],
                'email': user['email'],
                'tenant_id': tenant_id, # <--- AHORA SE INCLUYE CORRECTAMENTE
                'exp': datetime.utcnow() + timedelta(hours=8)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            app.logger.info("--- FIN PROCESO DE LOGIN (EXITOSO) ---")
            return jsonify({'token': token})
        else:
            app.logger.warning("LOGIN FALLIDO: La contraseña NO coincide.")
            return jsonify({'message': 'Credenciales inválidas'}), 401
    
    except Exception as e:
        app.logger.error(f"Error crítico en el login: {e}\n{traceback.format_exc()}")
        return jsonify({"error": "Ocurrió un error en el servidor"}), 500
    finally:
        if 'cursor' in locals() and cursor: cursor.close()
        if 'conn' in locals() and conn.is_connected(): conn.close()

def token_required(f):
    """
    Decorador para verificar que un token JWT válido esté presente en las cabeceras
    de la petición.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # El token se espera en el formato 'Bearer <token>'
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token con formato incorrecto'}), 401

        if not token:
            return jsonify({'message': 'Token es requerido'}), 401

        try:
            # Decodifica el token usando la misma clave secreta
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Extraer y almacenar el tenant_id en el contexto global
            tenant_id = data.get('tenant_id')
            if not tenant_id:
                return jsonify({'message': 'Token inválido: falta información de inquilino'}), 401
            
            g.current_tenant_id = tenant_id
            g.current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'El token ha expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido'}), 401
        except Exception as e:
            return jsonify({'message': f'Error al procesar el token: {e}'}), 401

        # Si el token es válido, permite que la petición continúe a la ruta original
        return f(*args, **kwargs)
    return decorated


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key == INTERNAL_API_KEY:
            return f(*args, **kwargs)
        else:
            # Log de acceso no autorizado
            app.logger.warning(f"Acceso no autorizado al API interno. Clave recibida: {api_key}")
            return jsonify({"error": "Acceso no autorizado"}), 401
    return decorated_function


# --- FUNCIÓN DE CONEXIÓN A LA BD ---
def get_db_connection():
    try:
        return mysql.connector.connect(
            host=os.getenv('DB_HOST'), user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'), port=int(os.getenv('DB_PORT')),
            database=os.getenv('DB_NAME')
        )
    except mysql.connector.Error as err:
        app.logger.error(f"Error de conexión a la base de datos: {err}")
        return None

# --- ✨ FUNCIONES AUXILIARES PARA MULTI-TENANCY ✨ ---
def get_current_tenant_id():
    """
    Obtiene el tenant_id del contexto actual de la petición.
    Debe usarse dentro de rutas protegidas con @token_required.
    """
    return getattr(g, 'current_tenant_id', None)

def add_tenant_filter(base_query, table_alias='', tenant_column='id_cliente'):
    """
    Agrega filtro de tenant a una consulta SQL.
    
    Args:
        base_query (str): La consulta SQL base
        table_alias (str): Alias de la tabla principal (opcional)
        tenant_column (str): Nombre de la columna que contiene el tenant_id
    
    Returns:
        tuple: (query_with_filter, tenant_id)
    """
    tenant_id = get_current_tenant_id()
    if not tenant_id:
        raise ValueError("No se encontró tenant_id en el contexto de la petición")
    
    # Agregar el prefijo de tabla si se proporciona
    column_ref = f"{table_alias}.{tenant_column}" if table_alias else tenant_column
    
    # Agregar filtro WHERE o AND según corresponda
    if "WHERE" in base_query.upper():
        filtered_query = f"{base_query} AND {column_ref} = %s"
    else:
        filtered_query = f"{base_query} WHERE {column_ref} = %s"
    
    return filtered_query, tenant_id

# --- ✨ NUEVO BLOQUE DE FUNCIONES AUXILIARES PARA NOTIFICACIONES ✨ ---

def get_honduras_time():
    """Devuelve la fecha y hora actual en la zona horaria de Honduras."""
    hn_timezone = pytz.timezone('America/Tegucigalpa')
    return datetime.now(hn_timezone)

def _send_task_to_bridge(task_data):
    """
    Función interna para enviar una tarea de notificación al servidor bridge.js.
    No detiene el flujo principal si bridge.js no está disponible.
    """
    try:
        bridge_url = os.getenv('BRIDGE_API_URL', 'https://34.63.21.5.sslip.io/bridge') + '/api/internal/queue_whatsapp_message'
        # Usamos un timeout corto para no bloquear la respuesta al usuario del CRM
        response = requests.post(bridge_url, json=task_data, timeout=5)
        if response.status_code == 200:
            app.logger.info(f"Tarea enviada exitosamente a bridge.js: {task_data.get('task_type')}")
            return True
        else:
            app.logger.error(f"Error al enviar tarea a bridge.js. Status: {response.status_code}, Body: {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        app.logger.error(f"No se pudo conectar con bridge.js para enviar la tarea. Error: {e}")
        return False

# --- FIN DEL NUEVO BLOQUE ---

def generate_secure_filename(doc_type, user_id, original_filename, sequence=None):
    """
    Genera un nombre de archivo completamente seguro y único.
    
    Args:
        doc_type: Tipo de documento ("CV", "ID", etc.)
        user_id: Identificador del usuario (cédula limpia)
        original_filename: Nombre original del archivo
        sequence: Número de secuencia para múltiples archivos (opcional)
    
    Returns:
        str: Nombre de archivo seguro y único
    """
    # Sanitizar el nombre original del archivo
    safe_original = re.sub(r'[^a-zA-Z0-9._-]', '_', original_filename)
    safe_original = re.sub(r'_{2,}', '_', safe_original)  # Reducir múltiples underscores
    
    # Obtener extensión de forma segura
    if '.' in safe_original:
        name_part, extension = safe_original.rsplit('.', 1)
        extension = extension.lower()[:10]  # Limitar longitud de extensión
    else:
        name_part = safe_original
        extension = 'bin'
    
    # Crear timestamp único
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]  # Incluir microsegundos
    
    # Crear hash único basado en contenido y timestamp
    hash_input = f"{doc_type}_{user_id}_{timestamp}_{name_part}"
    file_hash = hashlib.md5(hash_input.encode()).hexdigest()[:8]
    
    # Construir nombre final
    components = [doc_type, user_id, timestamp, file_hash]
    if sequence:
        components.append(f"seq{sequence}")
    
    final_name = "_".join(components) + f".{extension}"
    
    # Asegurar que no exceda límites del sistema de archivos
    if len(final_name) > 255:
        final_name = final_name[:250] + f".{extension}"
    
    return final_name

def clean_phone_number(phone_str):
    """Limpia y estandariza los números de teléfono para Honduras."""
    if not phone_str:
        return None
    # Eliminar todos los caracteres que no sean dígitos
    digits = re.sub(r'\D', '', str(phone_str))
    # Si el número ya empieza con 504 y tiene 11 dígitos, es correcto
    if digits.startswith('504') and len(digits) == 11:
        return digits
    # Si tiene 8 dígitos, le añadimos el código de país
    if len(digits) == 8:
        return '504' + digits
    # En otros casos, devolvemos el número limpio, pero podría ser inválido
    return digits

# --- RUTA DE PRUEBA ---
@app.route('/')
def index():
    return "Servidor del CRM Henmir está en línea. Versión Definitiva con Asistente IA."

# ===============================================================
# SECCIÓN 1: ASISTENTE DE IA (OpenAI)
# ===============================================================

# AÑADE ESTA NUEVA FUNCIÓN AYUDANTE al inicio de la SECCIÓN 1 en app.py

def _get_candidate_id(conn, candidate_id: int = None, identity_number: str = None) -> int:
    """Función interna para obtener el id_afiliado. Prioriza el candidate_id si está presente."""
    if candidate_id:
        return candidate_id
    
    if identity_number:
        cursor = conn.cursor(dictionary=True)
        clean_identity = str(identity_number).replace('-', '').strip()
        tenant_id = get_current_tenant_id()
        query = "SELECT id_afiliado FROM Afiliados WHERE identidad = %s AND id_cliente = %s LIMIT 1"
        cursor.execute(query, (clean_identity, tenant_id))
        result = cursor.fetchone()
        cursor.close()
        if result:
            return result['id_afiliado']
            
    return None

# --- Funciones que el Asistente de IA puede llamar ---
def get_candidates_by_ids(ids: list):
    """Obtiene información de contacto de candidatos por sus IDs."""
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    try:
        safe_ids = [int(i) for i in ids]
        if not safe_ids: return json.dumps([])
        tenant_id = get_current_tenant_id()
        placeholders = ','.join(['%s'] * len(safe_ids))
        query = f"SELECT id_afiliado, nombre_completo, telefono FROM Afiliados WHERE id_afiliado IN ({placeholders}) AND id_cliente = %s"
        cursor.execute(query, tuple(safe_ids) + (tenant_id,))
        results = cursor.fetchall()
        for r in results:
            r['telefono'] = clean_phone_number(r.get('telefono'))
        return json.dumps(results)
    finally:
        cursor.close()
        conn.close()

def get_candidates_by_tag(tag_name: str):
    """Obtiene información de contacto de candidatos que tienen una etiqueta específica."""
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        query = """
            SELECT a.id_afiliado, a.nombre_completo, a.telefono 
            FROM Afiliados a 
            JOIN Afiliado_Tags at ON a.id_afiliado = at.id_afiliado 
            JOIN Tags t ON at.id_tag = t.id_tag 
            WHERE t.nombre_tag = %s AND a.id_cliente = %s AND t.id_cliente = %s
        """
        cursor.execute(query, (tag_name, tenant_id, tenant_id))
        results = cursor.fetchall()
        for r in results:
            r['telefono'] = clean_phone_number(r.get('telefono'))
        return json.dumps(results)
    finally:
        cursor.close()
        conn.close()

def get_vacancy_details(vacancy_name: str):
    """Obtiene detalles de una vacante por su nombre."""
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT cargo_solicitado, empresa FROM Vacantes v JOIN Clientes c ON v.id_cliente = c.id_cliente WHERE v.cargo_solicitado LIKE %s LIMIT 1"
        cursor.execute(query, (f"%{vacancy_name}%",))
        result = cursor.fetchone()
        return json.dumps(result)
    finally:
        cursor.close()
        conn.close()
        
        
def get_candidate_id_by_identity(identity_number: str):
    """Obtiene el ID numérico de un afiliado a partir de su número de identidad."""
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    try:
        clean_identity = str(identity_number).replace('-', '').strip()
        tenant_id = get_current_tenant_id()
        query = "SELECT id_afiliado FROM Afiliados WHERE identidad = %s AND id_cliente = %s LIMIT 1"
        cursor.execute(query, (clean_identity, tenant_id))
        result = cursor.fetchone()
        return json.dumps(result)
    finally:
        cursor.close()
        conn.close()
        
    

def postulate_candidate_to_vacancy(vacancy_id: int, candidate_id: int = None, identity_number: str = None, comments: str = ""):
    """Postula un candidato a una vacante usando su ID de candidato o su número de identidad."""
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    
    # Usamos la función ayudante para encontrar el ID correcto
    final_candidate_id = _get_candidate_id(conn, candidate_id, identity_number)
    
    if not final_candidate_id:
        return json.dumps({"success": False, "error": f"No se pudo encontrar al candidato con los datos proporcionados."})

    cursor = conn.cursor()
    try:
        # Verificar si la postulación ya existe
        cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_afiliado = %s AND id_vacante = %s", (final_candidate_id, vacancy_id))
        if cursor.fetchone():
            return json.dumps({"success": False, "message": f"El candidato (ID: {final_candidate_id}) ya ha postulado a esta vacante."})
        
        # Insertar la nueva postulación
        sql = "INSERT INTO Postulaciones (id_afiliado, id_vacante, fecha_aplicacion, estado, comentarios) VALUES (%s, %s, NOW(), 'Recibida', %s)"
        cursor.execute(sql, (final_candidate_id, vacancy_id, comments))
        conn.commit()
        return json.dumps({"success": True, "message": f"Postulación del candidato (ID: {final_candidate_id}) registrada correctamente."})
    except Exception as e:
        conn.rollback()
        return json.dumps({"success": False, "error": str(e)})
    finally:
        cursor.close()
        conn.close()        
        
                

@app.route('/api/assistant/command', methods=['POST'])
@token_required
def assistant_command():
    data = request.get_json()
    user_prompt = data.get('prompt')
    history = data.get('history', [])
    
    if not user_prompt:
        return jsonify({"error": "Prompt es requerido"}), 400

    try:
        messages = [
            {"role": "system", "content": """
                Eres un asistente de reclutamiento experto para la agencia Henmir. Tu personalidad es proactiva, eficiente y directa.
                REGLAS CRÍTICAS:
                1.  Uso de Herramientas: Tu función principal es ejecutar acciones usando las herramientas proporcionadas. Para cualquier acción que implique buscar, postular, agendar o actualizar datos, DEBES usar una herramienta. NO inventes información.
                2.  Contexto: Presta mucha atención al historial de la conversación para entender órdenes de seguimiento como "postula al segundo candidato" o "usa el mismo mensaje".
                3.  Clarificación: Si una orden es ambigua (ej. "postula a Juan a la vacante de ventas" y hay varias vacantes de ventas), DEBES hacer una pregunta para clarificar antes de usar una herramienta.
                4.  Identificadores: Para acciones sobre candidatos o vacantes, prioriza siempre el uso de IDs numéricos si están disponibles en el historial. Si no, usa nombres o números de identidad para buscarlos.
                """
            }
        ]
        for item in history:
            if item.get('user'): messages.append({"role": "user", "content": item.get('user')})
            if item.get('assistant'): messages.append({"role": "assistant", "content": item.get('assistant')})
        messages.append({"role": "user", "content": user_prompt})

        tools = [
            {"type": "function", "function": {"name": "search_candidates_tool", "description": "Busca candidatos.", "parameters": {"type": "object", "properties": {"term": {"type": "string"}, "tags": {"type": "string"}, "experience": {"type": "string"}, "city": {"type": "string"}, "recency_days": {"type": "integer"}}, "required": []}}},
            # --- ✨ NUEVA HERRAMIENTA AÑADIDA AQUÍ ✨ ---
            {"type": "function", "function": {"name": "get_active_vacancies_details_tool", "description": "Obtiene una lista detallada de vacantes activas, incluyendo requisitos, ciudad y salario. Útil para cuando el reclutador quiere ver las opciones disponibles.", "parameters": {"type": "object", "properties": {"city": {"type": "string", "description": "Opcional. La ciudad para filtrar."}, "keyword": {"type": "string", "description": "Opcional. Palabra clave para buscar en el cargo o requisitos."}}, "required": []}}},
            {"type": "function", "function": {"name": "postulate_candidate_to_vacancy", "description": "Postula un candidato a una vacante usando su ID interno o su número de identidad.", "parameters": {"type": "object", "properties": {"vacancy_id": {"type": "integer"}, "candidate_id": {"type": "integer"}, "identity_number": {"type": "string"}, "comments": {"type": "string"}}, "required": ["vacancy_id"]}}},
            {"type": "function", "function": {"name": "prepare_whatsapp_campaign_tool", "description": "Prepara una campaña de WhatsApp. Usa el mensaje si el usuario lo provee; si no, usa una plantilla.", "parameters": {"type": "object", "properties": {"message_body": {"type": "string", "description": "Opcional. El cuerpo del mensaje a enviar."}, "template_id": {"type": "integer", "description": "Opcional. El ID de la plantilla de mensaje a usar."}, "candidate_ids": {"type": "string", "description": "Opcional. IDs o identidades de candidatos, separados por comas."}, "vacancy_id": {"type": "integer", "description": "Opcional. Filtra candidatos por ID de vacante."}}, "required": []}}},
            {"type": "function", "function": {"name": "schedule_interview_tool", "description": "Agenda una nueva entrevista.", "parameters": {"type": "object", "properties": {"postulation_id": {"type": "integer"}, "interview_date": {"type": "string"}, "interview_time": {"type": "string"}, "interviewer": {"type": "string"}, "notes": {"type": "string"}}, "required": ["postulation_id", "interview_date", "interview_time", "interviewer"]}}},
            {"type": "function", "function": {"name": "update_application_status_tool", "description": "Actualiza el estado de una postulación.", "parameters": {"type": "object", "properties": {"postulation_id": {"type": "integer"}, "new_status": {"type": "string"}}, "required": ["postulation_id", "new_status"]}}},
            {"type": "function", "function": {"name": "get_report_data_tool", "description": "Obtiene los datos de un reporte interno.", "parameters": {"type": "object", "properties": {"report_name": {"type": "string"}},"required": ["report_name"]}}},
            {"type": "function", "function": {"name": "get_vacancy_id_by_name_tool", "description": "Busca el ID numérico de una vacante por su nombre.", "parameters": {"type": "object", "properties": {"vacancy_name": {"type": "string"}, "company_name": {"type": "string"}},"required": ["vacancy_name"]}}}
        ]
        
        response = openai_client.chat.completions.create(
            model="gpt-4o", messages=messages, tools=tools, tool_choice="auto"
        )
        response_message = response.choices[0].message
        tool_calls = response_message.tool_calls

        if tool_calls:
            available_functions = {
                "search_candidates_tool": search_candidates_tool,
                "postulate_candidate_to_vacancy": postulate_candidate_to_vacancy,
                "prepare_whatsapp_campaign_tool": prepare_whatsapp_campaign_tool,
                "schedule_interview_tool": schedule_interview_tool,
                "update_application_status_tool": update_application_status_tool,
                "get_report_data_tool": get_report_data_tool,
                "get_vacancy_id_by_name_tool": get_vacancy_id_by_name_tool,
                # --- ✨ NUEVA FUNCIÓN AÑADIDA AL DICCIONARIO ✨ ---
                "get_active_vacancies_details_tool": get_active_vacancies_details_tool,
            }
            messages.append(response_message)
            last_function_response = None
            last_function_name = ""
            for tool_call in tool_calls:
                function_name = tool_call.function.name
                function_args = json.loads(tool_call.function.arguments)
                function_to_call = available_functions.get(function_name)
                if function_to_call:
                    function_response = function_to_call(**function_args)
                    last_function_response = function_response
                    last_function_name = function_name
                else:
                    function_response = json.dumps({"error": f"Función '{function_name}' no encontrada."})
                messages.append({
                    "tool_call_id": tool_call.id, "role": "tool", "name": function_name,
                    "content": function_response if isinstance(function_response, str) else json.dumps(function_response),
                })
            final_response_message = openai_client.chat.completions.create(
                model="gpt-4o", messages=messages
            ).choices[0].message.content
            if last_function_name == 'prepare_whatsapp_campaign_tool':
                campaign_data = json.loads(last_function_response)
                if campaign_data.get("data"):
                    return jsonify({"type": "whatsapp_campaign_prepared", "text_response": final_response_message, "campaign_data": campaign_data["data"]})
            return jsonify({"type": "text_response", "data": final_response_message})
        else:
            return jsonify({"type": "text_response", "data": response_message.content})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    



def prepare_whatsapp_campaign_tool(message_body: str, candidate_id: int = None, identity_number: str = None, candidate_ids: str = None, vacancy_id: int = None, application_date: str = None):
    """
    Prepara una campaña de WhatsApp. Busca candidatos y devuelve su info de contacto junto con el mensaje.
    Puede buscar por ID/identidad de candidato DIRECTAMENTE, por una lista de IDs, o filtrar postulantes por vacante.
    """
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    
    try:
        final_message_body = message_body
        if not final_message_body:
            # Si la IA no extrajo un mensaje, buscamos la plantilla 1 por defecto (o la que prefieras)
            cursor.execute("SELECT cuerpo_mensaje FROM Whatsapp_Templates WHERE id_template = 1")
            template = cursor.fetchone()
            final_message_body = template['cuerpo_mensaje'] if template else "Hola [name], te contactamos de Henmir."

        candidates = []
        # ✨ LÓGICA DE BÚSQUEDA CORREGIDA Y SIMPLIFICADA ✨
        # Prioridad 1: Si se da un ID o identidad individual.
        if candidate_id or identity_number:
            target_id = _get_candidate_id(conn, candidate_id, identity_number)
            if target_id:
                cursor.execute("SELECT id_afiliado, nombre_completo, telefono FROM Afiliados WHERE id_afiliado = %s", (target_id,))
                candidates = cursor.fetchall()
        # Prioridad 2: Si se da una lista de IDs/identidades.
        elif candidate_ids:
            id_list = re.findall(r'\b\d+\b', candidate_ids) # Buscamos cualquier número
            if id_list:
                placeholders = ','.join(['%s'] * len(id_list))
                sql = f"SELECT id_afiliado, nombre_completo, telefono FROM Afiliados WHERE id_afiliado IN ({placeholders}) OR identidad IN ({placeholders})"
                cursor.execute(sql, id_list * 2)
                candidates = cursor.fetchall()
        # Prioridad 3: Si no, filtramos por vacante.
        elif vacancy_id:
            # Lógica para filtrar por vacante (sin cambios)
            pass

        if not candidates:
            return json.dumps({"data": {"candidates": [], "message": ""}, "message": "No se encontraron candidatos con esos criterios."})

        recipients = []
        for cand in candidates:
            clean_phone = clean_phone_number(cand.get('telefono'))
            if clean_phone:
                recipients.append({"nombre_completo": cand['nombre_completo'], "telefono": clean_phone})
        
        return json.dumps({"data": {"recipients": recipients, "message_body": final_message_body}, "message": f"He preparado una campaña para {len(recipients)} candidato(s) validados."})

    finally:
        cursor.close()
        conn.close()

    

def schedule_interview_tool(postulation_id: int, interview_date: str, interview_time: str, interviewer: str, notes: str = ""):
    """
    Agenda una nueva entrevista para una postulación existente.
    'interview_date' debe estar en formato YYYY-MM-DD.
    'interview_time' debe estar en formato HH:MM:SS (24 horas).
    """
    conn = get_db_connection()
    if not conn: 
        return json.dumps({"success": False, "error": "Fallo en la conexión a la BD."})

    cursor = conn.cursor()
    try:
        # Combinamos la fecha y la hora para el formato DATETIME de la base de datos
        datetime_str = f"{interview_date} {interview_time}"

        # Insertamos la nueva entrevista
        sql_insert = "INSERT INTO Entrevistas (id_postulacion, fecha_hora, entrevistador, resultado, observaciones) VALUES (%s, %s, %s, 'Programada', %s)"
        cursor.execute(sql_insert, (postulation_id, datetime_str, interviewer, notes))

        # Actualizamos el estado de la postulación a 'En Entrevista'
        sql_update = "UPDATE Postulaciones SET estado = 'En Entrevista' WHERE id_postulacion = %s"
        cursor.execute(sql_update, (postulation_id,))

        conn.commit()
        return json.dumps({"success": True, "message": f"Entrevista agendada exitosamente para la postulación {postulation_id}."})

    except mysql.connector.Error as err:
        conn.rollback()
        # Error común: la postulación no existe.
        if err.errno == 1452:
            return json.dumps({"success": False, "error": f"No se pudo agendar. La postulación con ID {postulation_id} no existe."})
        return json.dumps({"success": False, "error": f"Error de base de datos: {str(err)}"})
    except Exception as e:
        conn.rollback()
        return json.dumps({"success": False, "error": f"Error inesperado: {str(e)}"})
    finally:
        cursor.close()
        conn.close()



def update_application_status_tool(postulation_id: int, new_status: str):
    """
    Actualiza el estado de una postulación existente.
    Los estados válidos son: 'Recibida', 'En Revisión', 'Pre-seleccionado', 'En Entrevista', 'Oferta', 'Contratado', 'Rechazado'.
    """
    valid_statuses = ['Recibida', 'En Revisión', 'Pre-seleccionado', 'En Entrevista', 'Oferta', 'Contratado', 'Rechazado']
    if new_status not in valid_statuses:
        return json.dumps({"success": False, "error": f"'{new_status}' no es un estado válido. Los estados permitidos son: {', '.join(valid_statuses)}"})

    conn = get_db_connection()
    if not conn: 
        return json.dumps({"success": False, "error": "Fallo en la conexión a la BD."})

    cursor = conn.cursor()
    try:
        sql = "UPDATE Postulaciones SET estado = %s WHERE id_postulacion = %s"
        cursor.execute(sql, (new_status, postulation_id))

        if cursor.rowcount == 0:
            conn.rollback()
            return json.dumps({"success": False, "error": f"No se encontró una postulación con el ID {postulation_id}."})

        conn.commit()
        return json.dumps({"success": True, "message": f"El estado de la postulación {postulation_id} se ha actualizado a '{new_status}'."})

    except Exception as e:
        conn.rollback()
        return json.dumps({"success": False, "error": f"Error inesperado al actualizar el estado: {str(e)}"})
    finally:
        cursor.close()
        conn.close()



def get_report_data_tool(report_name: str):
    """
    Obtiene los datos de un reporte específico del sistema para poder analizarlos o resumirlos.
    'report_name' debe ser uno de los IDs de reporte válidos, como 'vacantes_activas' o 'pagos_pendientes'.
    """
    # --- Esta función simula una llamada a nuestra propia API de reportes ---
    # No podemos usar requests.get aquí fácilmente en un entorno de desarrollo de Flask,
    # así que replicamos la lógica de la función get_reports.

    if not report_name:
        return json.dumps({"error": "Se requiere el nombre del reporte"})

    conn = get_db_connection()
    if not conn: 
        return json.dumps({"error": "DB connection failed"})

    cursor = conn.cursor(dictionary=True)
    sql = "" # Dejaremos esto vacío ya que la lógica está en get_reports

    try:
        # Reutilizamos la lógica de la función get_reports para no repetir código
        # (En una app más grande, esto se refactorizaría a una función interna común)

        # --- Aquí pegamos la lógica de la función get_reports ---
        # Para mantener la simplicidad, por ahora solo implementaremos la llamada para dos reportes clave.
        # El asistente aprenderá el patrón.
        if report_name == 'vacantes_activas':
            sql = """
                SELECT v.cargo_solicitado, c.empresa, 
                       (SELECT COUNT(*) FROM Postulaciones p WHERE p.id_vacante = v.id_vacante) as total_postulaciones
                FROM Vacantes v JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE v.estado = 'Abierta' ORDER BY total_postulaciones DESC;
            """
        elif report_name == 'pagos_pendientes':
            sql = """
                SELECT c.empresa, v.cargo_solicitado, (co.tarifa_servicio - co.monto_pagado) AS saldo_pendiente
                FROM Contratados co
                JOIN Vacantes v ON co.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE (co.tarifa_servicio - co.monto_pagado) > 0 ORDER BY saldo_pendiente DESC;
            """
        else:
             return json.dumps({"error": f"El reporte '{report_name}' no es soportado por el asistente en este momento."})

        cursor.execute(sql)
        results = cursor.fetchall()

        # Convertimos a JSON compatible
        for row in results:
            for key, value in row.items():
                if isinstance(value, (datetime, date)):
                    row[key] = value.isoformat()
                elif isinstance(value, Decimal):
                    row[key] = float(value)

        # Limitamos la cantidad de datos para no sobrecargar al modelo
        if len(results) > 15:
            summary = {"summary": f"Se encontraron {len(results)} registros. Mostrando los primeros 15.", "data": results[:15]}
            return json.dumps(summary)

        return json.dumps(results)

    except Exception as e:
        return json.dumps({"error": f"Error al generar data para el reporte: {str(e)}"})
    finally:
        cursor.close()
        conn.close()



def get_vacancy_id_by_name_tool(vacancy_name: str, company_name: str = None):
    """
    Busca el ID numérico de una vacante a partir de su nombre y, opcionalmente, el nombre de la empresa.
    Esencial para cuando el usuario pide postular a alguien a una vacante por nombre en lugar de por ID.
    """
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT v.id_vacante FROM Vacantes v"
        params = []
        conditions = []

        conditions.append("v.cargo_solicitado LIKE %s")
        params.append(f"%{vacancy_name}%")

        if company_name:
            query += " JOIN Clientes c ON v.id_cliente = c.id_cliente"
            conditions.append("c.empresa LIKE %s")
            params.append(f"%{company_name}%")
        
        query += " WHERE " + " AND ".join(conditions) + " LIMIT 1"
        
        cursor.execute(query, tuple(params))
        result = cursor.fetchone()
        
        if result:
            return json.dumps(result)
        else:
            return json.dumps({"error": "No se encontró una vacante que coincida con esos criterios."})
    finally:
        cursor.close()
        conn.close()
        
# --- ✨ NUEVA FUNCIÓN-HERRAMIENTA PARA EL ASISTENTE INTERNO ✨ ---
def get_active_vacancies_details_tool(city: str = None, keyword: str = None):
    """
    Busca vacantes activas y devuelve sus detalles completos, incluyendo cargo,
    empresa, ciudad, salario y requisitos. Ideal para que el reclutador evalúe las vacantes.
    """
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT v.id_vacante, v.cargo_solicitado, c.empresa, v.ciudad, v.salario, v.requisitos
            FROM Vacantes v JOIN Clientes c ON v.id_cliente = c.id_cliente
            WHERE v.estado = 'Abierta'
        """
        params = []
        if city:
            query += " AND v.ciudad LIKE %s"
            params.append(f"%{city}%")
        if keyword:
            query += " AND (v.cargo_solicitado LIKE %s OR v.requisitos LIKE %s)"
            params.extend([f"%{keyword}%", f"%{keyword}%"])
        
        cursor.execute(query, tuple(params))
        results = cursor.fetchall()
        # Convertir Decimal a float para que sea serializable a JSON
        for row in results:
            if isinstance(row.get('salario'), Decimal):
                row['salario'] = float(row['salario'])
        return json.dumps(results)
    finally:
        cursor.close()
        conn.close()



# ===============================================================
# SECCIÓN 1.5: HERRAMIENTAS ADICIONALES (PARA CHATBOT EXTERNO)
# ===============================================================


def search_vacancies_tool(city: str = None, keyword: str = None):
    """
    (Herramienta para el bot de WhatsApp) Busca TODAS las vacantes disponibles.
    Devuelve solo información pública (cargo, ciudad), nunca datos sensibles.
    """
    app.logger.info(f"[Herramienta Chatbot] Buscando TODAS las vacantes: ciudad='{city}', keyword='{keyword}'")
    conn = get_db_connection()
    if not conn: 
        app.logger.error("Error de conexión a BD en search_vacancies_tool")
        return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    
    try:
        # ✨ CAMBIO: Consulta sin ningún LIMIT.
        query = "SELECT cargo_solicitado, ciudad FROM Vacantes WHERE estado = 'Abierta'"
        params = []
        
        if city:
            # Usamos LOWER() para hacer la búsqueda insensible a mayúsculas/minúsculas
            query += " AND LOWER(ciudad) LIKE LOWER(%s)"
            params.append(f"%{city}%")
        
        if keyword:
            # Hacemos la búsqueda de palabra clave también insensible a mayúsculas/minúsculas
            query += " AND (LOWER(cargo_solicitado) LIKE LOWER(%s) OR LOWER(requisitos) LIKE LOWER(%s))"
            params.extend([f"%{keyword}%", f"%{keyword}%"])
            
        cursor.execute(query, tuple(params))
        results = cursor.fetchall()
        
        app.logger.info(f"Encontradas {len(results)} vacantes en la base de datos")
        return json.dumps(results)
        
    except Exception as e:
        app.logger.error(f"Error en search_vacancies_tool: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return json.dumps({"error": str(e)})
    finally:
        cursor.close()
        conn.close()

#
# NOTA: No necesitamos añadir 'bot_validate_registration' aquí porque
# ya tenemos la ruta /api/bot_tools/validate_registration que hace esa función.
# Llamar a una ruta desde el bot es más limpio. 
# Si decidiéramos unificarlo, lo haríamos, pero por ahora la ruta dedicada es suficiente.
#



# ===============================================================
# SECCIÓN 2: WEBHOOK Y GESTIÓN DE DATOS MASIVOS
# ===============================================================

@app.route('/api/webhook/new-candidate-jsonp', methods=['GET'])
def webhook_new_candidate_jsonp():
    callback_function = request.args.get('callback', 'callback')
    api_key = request.args.get('apiKey')
    if not api_key or api_key != os.getenv('WEBHOOK_API_KEY'):
        error_payload = json.dumps({"success": False, "error": "Acceso no autorizado"})
        return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')
    conn = get_db_connection()
    if not conn:
        error_payload = json.dumps({"success": False, "error": "Error de conexión a la BD"})
        return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')
    cursor = conn.cursor()
    try:
        record = request.args
        identidad = str(record.get('identidad', '')).replace('-', '').strip()
        if not identidad: raise ValueError("El número de identidad es obligatorio.")

        # --- CAMBIO CLAVE AQUÍ ---
        # Si el email viene vacío o no existe, lo convertimos a None (que se traduce en NULL en SQL)
        email = record.get('email') or None

        rotativos = 1 if str(record.get('disponibilidad_rotativos')).strip().lower() == 'si' else 0
        transporte = 1 if str(record.get('transporte_propio')).strip().lower() == 'si' else 0
        
        sql_upsert = """
            INSERT INTO Afiliados (fecha_registro, nombre_completo, identidad, telefono, email, experiencia, ciudad, grado_academico, cv_url, observaciones, contrato_url, disponibilidad_rotativos, transporte_propio)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                nombre_completo=VALUES(nombre_completo), telefono=VALUES(telefono), email=VALUES(email),
                experiencia=VALUES(experiencia), ciudad=VALUES(ciudad), grado_academico=VALUES(grado_academico),
                cv_url=VALUES(cv_url), observaciones=VALUES(observaciones), contrato_url=VALUES(contrato_url),
                disponibilidad_rotativos=VALUES(disponibilidad_rotativos), transporte_propio=VALUES(transporte_propio);
        """

        # REEMPLAZA LAS DOS LÍNEAS DE data_tuple Y cursor.execute CON ESTE BLOQUE COMPLETO

        # Como Google Forms no envía la fecha, generamos la fecha y hora actual AHORA.
        fecha_de_registro_actual = datetime.now()

        # Construimos la tupla de datos usando nuestra nueva variable de fecha.
        data_tuple = (
            fecha_de_registro_actual, 
            record.get('nombre_completo'), 
            identidad,
            record.get('telefono'), 
            email,
            record.get('experiencia'),
            record.get('ciudad'), 
            record.get('grado_academico'), 
            record.get('cv_url'),
            record.get('observaciones'), 
            record.get('contrato_url'), 
            rotativos, 
            transporte
        )
        
        # Ejecutamos la consulta SQL con la tupla que AHORA SÍ contiene una fecha válida.
        cursor.execute(sql_upsert, data_tuple)
        
        # Ejecutamos la consulta
        cursor.execute(sql_upsert, data_tuple)
        
        conn.commit()
        success_payload = json.dumps({"success": True, "message": "Candidato sincronizado vía JSONP."})
        return Response(f"{callback_function}({success_payload})", mimetype='application/javascript')
    except Exception as e:
        conn.rollback()
        error_payload = json.dumps({"success": False, "error": str(e)})
        return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')
    finally:
        cursor.close()
        conn.close()

@app.route('/api/download-template', methods=['GET'])
@token_required
def download_template():
    data_type = request.args.get('type', 'afiliados')
    TEMPLATE_HEADERS = {
        'afiliados': [
            'Marca temporal', 'Contrato(respuesta de si y no )', 'Nombre completo:', 'No. de identidad Sin Guiones',
            'Numero de telefono', 'Dirección de correo electrónico',
            'Cuentenos sus areas de experiencia. Necesitamos una descripción detallada de su experiencia laboral. Esta información es clave para realizar una búsqueda efectiva y presentarle a las vacantes más adecuadas',
            'Ciudad', '¿cuenta usted con disponibilidad de trabajar turnos rotativos?', '¿Cuenta con transporte propio ?',
            '¿Cual es su grado academico ?', 'Dejenos Su Cv(Enlace a Google Drive)',
            'Foto revés y derecho de su tarjeta de identidad:(enlace Google Drive )', 'Estado', 'Observaciones'
        ],
        'clientes': ['empresa', 'contacto_nombre', 'telefono', 'email', 'sector', 'observaciones'],
        'vacantes': ['id_cliente (ID numérico del cliente)', 'cargo_solicitado', 'ciudad', 'requisitos', 'salario', 'estado'],
        'postulaciones': ['identidad_candidato (Sin guiones)', 'id_vacante (ID numérico de la vacante)', 'comentarios', 'estado'],
        'entrevistas': ['id_postulacion', 'fecha_hora (YYYY-MM-DD HH:MM:SS)', 'entrevistador', 'resultado', 'observaciones'],
        'contratados': ['id_afiliado', 'id_vacante', 'fecha_contratacion (YYYY-MM-DD)', 'salario_final']
    }
    headers = TEMPLATE_HEADERS.get(data_type)
    if not headers:
        return jsonify({"success": False, "error": "Tipo de plantilla no válido."}), 400
    df = pd.DataFrame(columns=headers)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name=data_type)
    output.seek(0)
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'plantilla_{data_type}.xlsx'
    )


@app.route('/api/upload-excel', methods=['POST'])
@token_required
def upload_excel():
    if 'file' not in request.files: return jsonify({"success": False, "error": "No se encontró ningún archivo."}), 400
    data_type = request.form.get('type', 'afiliados')
    file = request.files['file']
    if file.filename == '': return jsonify({"success": False, "error": "No se seleccionó ningún archivo."}), 400
    if not (file.filename.endswith('.xlsx') or file.filename.endswith('.xls')): return jsonify({"success": False, "error": "Formato de archivo no válido."}), 400

    try:
        df = pd.read_excel(file, engine='openpyxl')
        # ✨ CORRECCIÓN PRINCIPAL AQUÍ ✨
        # Reemplazamos los valores vacíos (NaN) de pandas por None de Python.
        # La condición ahora se aplica a la tabla de datos (df) misma.
        df = df.astype(object).where(df.notna(), None)

        conn = get_db_connection()
        if not conn: return jsonify({"success": False, "error": "Error de conexión a la BD."}), 500
        cursor = conn.cursor()
        processed_count = 0

        if data_type == 'afiliados':
            # La lógica para afiliados se mantiene igual, si la tenías.
            # Por ahora la dejamos pasar para enfocarnos en clientes.
            pass
        
        # ✨ LÓGICA PARA CLIENTES AÑADIDA AQUÍ ✨
        elif data_type == 'clientes':
            # Columnas esperadas en la plantilla de clientes
            # ['empresa', 'contacto_nombre', 'telefono', 'email', 'sector', 'observaciones']
            for _, row in df.iterrows():
                # Validamos que la empresa (campo obligatorio) no esté vacía
                if not row.get('empresa'):
                    continue # Si no hay nombre de empresa, saltamos esta fila

                sql = """
                    INSERT INTO Clientes (empresa, contacto_nombre, telefono, email, sector, observaciones)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        contacto_nombre=VALUES(contacto_nombre), telefono=VALUES(telefono),
                        email=VALUES(email), sector=VALUES(sector), observaciones=VALUES(observaciones);
                """
                params = (
                    row.get('empresa'),
                    row.get('contacto_nombre'),
                    row.get('telefono'),
                    row.get('email'),
                    row.get('sector'),
                    row.get('observaciones')
                )
                cursor.execute(sql, params)
                processed_count += 1
        
        elif data_type == 'postulaciones':
            # La lógica para postulaciones se mantiene igual, si la tenías.
            pass

        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({"success": True, "message": f"{processed_count} registros de '{data_type}' procesados correctamente."})

    except Exception as e:
        # Devolvemos el error específico para facilitar la depuración
        return jsonify({"success": False, "error": f"Error al procesar el archivo: {str(e)}"}), 500

# ===============================================================
# SECCIÓN 3: GESTIÓN DE ETIQUETAS Y COMUNICACIONES
# ===============================================================
@app.route('/api/tags', methods=['GET', 'POST'])
@token_required
def handle_tags():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Tags WHERE id_cliente = %s ORDER BY nombre_tag", (tenant_id,))
            return jsonify(cursor.fetchall())
        
        elif request.method == 'POST':
            data = request.get_json()
            nombre_tag = data.get('nombre_tag')
            if not nombre_tag:
                return jsonify({"success": False, "error": "El nombre del tag es requerido."}), 400
            
            cursor.execute("INSERT INTO Tags (nombre_tag, id_cliente) VALUES (%s, %s)", (nombre_tag, tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Tag creado exitosamente.", "id_tag": cursor.lastrowid}), 201
    except mysql.connector.Error as err:
        if err.errno == 1062:  # Duplicate entry
            return jsonify({"success": False, "error": "Ya existe un tag con ese nombre."}), 409
        return jsonify({"success": False, "error": f"Error de base de datos: {str(err)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/candidate/<int:id_afiliado>/tags', methods=['GET', 'POST', 'DELETE'])
@token_required
def handle_candidate_tags(id_afiliado):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        # Verificar que el candidato pertenece al tenant
        cursor.execute("SELECT id_afiliado FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (id_afiliado, tenant_id))
        if not cursor.fetchone():
            return jsonify({"error": "Candidato no encontrado"}), 404
        
        if request.method == 'GET':
            sql = """
                SELECT T.id_tag, T.nombre_tag 
                FROM Afiliado_Tags AT 
                JOIN Tags T ON AT.id_tag = T.id_tag 
                WHERE AT.id_afiliado = %s AND T.id_cliente = %s
            """
            cursor.execute(sql, (id_afiliado, tenant_id))
            return jsonify(cursor.fetchall())
        elif request.method == 'POST':
            data = request.get_json()
            id_tag = data.get('id_tag')
            if not id_tag: return jsonify({"error": "Se requiere id_tag"}), 400
            
            # Verificar que el tag pertenece al tenant
            cursor.execute("SELECT id_tag FROM Tags WHERE id_tag = %s AND id_cliente = %s", (id_tag, tenant_id))
            if not cursor.fetchone():
                return jsonify({"error": "Tag no encontrado"}), 404
            
            cursor.execute("INSERT INTO Afiliado_Tags (id_afiliado, id_tag, id_cliente) VALUES (%s, %s, %s)", (id_afiliado, id_tag, tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Etiqueta asignada."}), 201
        elif request.method == 'DELETE':
            data = request.get_json()
            id_tag = data.get('id_tag')
            if not id_tag: return jsonify({"error": "Se requiere id_tag"}), 400
            cursor.execute("DELETE FROM Afiliado_Tags WHERE id_afiliado = %s AND id_tag = %s AND id_cliente = %s", (id_afiliado, id_tag, tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Etiqueta removida."})
    except mysql.connector.Error as err:
        if err.errno == 1062: return jsonify({"success": False, "error": "El candidato ya tiene esta etiqueta."}), 409
        return jsonify({"success": False, "error": str(err)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/templates', methods=['GET', 'POST'])
@token_required
def handle_email_templates():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT id_template, nombre_plantilla, asunto, fecha_creacion FROM Email_Templates WHERE id_cliente = %s ORDER BY nombre_plantilla", (tenant_id,))
            return jsonify(cursor.fetchall())
        elif request.method == 'POST':
            data = request.get_json()
            sql = "INSERT INTO Email_Templates (nombre_plantilla, asunto, cuerpo_html, id_cliente) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (data['nombre_plantilla'], data['asunto'], data['cuerpo_html'], tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Plantilla creada."}), 201
    finally:
        cursor.close()
        conn.close()

@app.route('/api/templates/<int:id_template>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def handle_single_template(id_template):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Email_Templates WHERE id_template = %s AND id_cliente = %s", (id_template, tenant_id))
            template = cursor.fetchone()
            if not template: return jsonify({"error": "Plantilla no encontrada"}), 404
            return jsonify(template)
        elif request.method == 'PUT':
            data = request.get_json()
            sql = "UPDATE Email_Templates SET nombre_plantilla=%s, asunto=%s, cuerpo_html=%s WHERE id_template=%s AND id_cliente=%s"
            cursor.execute(sql, (data['nombre_plantilla'], data['asunto'], data['cuerpo_html'], id_template, tenant_id))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({"error": "Plantilla no encontrada"}), 404
            return jsonify({"success": True, "message": "Plantilla actualizada."})
        elif request.method == 'DELETE':
            cursor.execute("DELETE FROM Email_Templates WHERE id_template = %s AND id_cliente = %s", (id_template, tenant_id))
            conn.commit()
            if cursor.rowcount == 0:
                return jsonify({"error": "Plantilla no encontrada"}), 404
            return jsonify({"success": True, "message": "Plantilla eliminada."})
    finally:
        cursor.close()
        conn.close()

@app.route('/api/communications/send-email', methods=['POST'])
@token_required
def send_email_from_template():
    data = request.get_json()
    id_afiliado = data.get('id_afiliado')
    id_template = data.get('id_template')

    if not id_afiliado or not id_template:
        return jsonify({"error": "Faltan id_afiliado o id_template"}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)

    try:
        tenant_id = get_current_tenant_id()
        
        cursor.execute("SELECT nombre_completo, email FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (id_afiliado, tenant_id))
        candidato = cursor.fetchone()
        if not candidato: return jsonify({"error": "Candidato no encontrado"}), 404

        cursor.execute("SELECT asunto, cuerpo_html FROM Email_Templates WHERE id_template = %s AND id_cliente = %s", (id_template, tenant_id))
        template = cursor.fetchone()
        if not template: return jsonify({"error": "Plantilla no encontrada"}), 404

        nombre_candidato = candidato['nombre_completo'].split(' ')[0]
        asunto_personalizado = template['asunto'].replace('[name]', nombre_candidato)
        cuerpo_personalizado = template['cuerpo_html'].replace('[name]', nombre_candidato)

        sender_email = os.getenv('GMAIL_USER')
        password = os.getenv('GMAIL_APP_PASSWORD')
        receiver_email = candidato['email']

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = asunto_personalizado
        msg.attach(MIMEText(cuerpo_personalizado, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()

        return jsonify({"success": True, "message": f"Correo enviado a {candidato['nombre_completo']}."})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# AÑADE ESTE NUEVO BLOQUE DE CÓDIGO en app.py

@app.route('/api/whatsapp-templates', methods=['GET', 'POST'])
@token_required
def handle_whatsapp_templates():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT id_template, nombre_plantilla FROM Whatsapp_Templates WHERE id_cliente = %s ORDER BY nombre_plantilla", (tenant_id,))
            return jsonify(cursor.fetchall())
        elif request.method == 'POST':
            data = request.get_json()
            sql = "INSERT INTO Whatsapp_Templates (nombre_plantilla, cuerpo_mensaje, id_cliente) VALUES (%s, %s, %s)"
            cursor.execute(sql, (data['nombre_plantilla'], data['cuerpo_mensaje'], tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Plantilla de WhatsApp creada."}), 201
    finally:
        cursor.close()
        conn.close()



# ===============================================================
# SECCIÓN 4: PIPELINE Y FLUJO DE TRABAJO
# ===============================================================
@app.route('/api/vacancies/<int:id_vacante>/pipeline', methods=['GET'])
@token_required
def get_vacancy_pipeline(id_vacante):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        # Verificar que la vacante pertenece al tenant
        cursor.execute("SELECT id_vacante FROM Vacantes WHERE id_vacante = %s AND id_cliente = %s", (id_vacante, tenant_id))
        if not cursor.fetchone():
            return jsonify({"error": "Vacante no encontrada"}), 404
        
        sql = """
            SELECT p.id_postulacion, p.estado, a.id_afiliado, a.nombre_completo, a.cv_url 
            FROM Postulaciones p 
            JOIN Afiliados a ON p.id_afiliado = a.id_afiliado 
            WHERE p.id_vacante = %s AND p.id_cliente = %s
        """
        cursor.execute(sql, (id_vacante, tenant_id))
        postulaciones = cursor.fetchall()
        pipeline = {'Recibida': [], 'En Revisión': [], 'Pre-seleccionado': [], 'En Entrevista': [], 'Oferta': [], 'Contratado': [], 'Rechazado': []}
        for post in postulaciones:
            estado = post.get('estado', 'Recibida')
            if estado in pipeline:
                pipeline[estado].append(post)
        return jsonify(pipeline)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/applications/<int:id_postulacion>/status', methods=['PUT'])
@token_required
def update_application_status(id_postulacion):
    data = request.get_json()
    nuevo_estado = data.get('estado')
    if not nuevo_estado: return jsonify({"error": "El nuevo estado es requerido"}), 400
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        tenant_id = get_current_tenant_id()
        
        # Verificar que la postulación pertenece al tenant
        cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (id_postulacion, tenant_id))
        if not cursor.fetchone():
            return jsonify({"error": "Postulación no encontrada"}), 404
        
        cursor.execute("UPDATE Postulaciones SET estado = %s WHERE id_postulacion = %s AND id_cliente = %s", (nuevo_estado, id_postulacion, tenant_id))
        conn.commit()
        return jsonify({"success": True, "message": f"Postulación actualizada a {nuevo_estado}."})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ===============================================================
# SECCIÓN 5: REPORTES Y KPIS
# ===============================================================
@app.route('/api/reports/kpi', methods=['GET'])
@token_required
def get_kpi_reports():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT AVG(DATEDIFF(fecha_cierre, fecha_apertura)) as avg_time_to_fill FROM Vacantes WHERE estado = 'Cerrada' AND fecha_cierre IS NOT NULL AND fecha_apertura IS NOT NULL")
        time_to_fill = cursor.fetchone()['avg_time_to_fill']
        cursor.execute("SELECT AVG(DATEDIFF(c.fecha_contratacion, p.fecha_aplicacion)) as avg_time_to_hire FROM Contratados c JOIN Postulaciones p ON c.id_afiliado = p.id_afiliado AND c.id_vacante = p.id_vacante")
        time_to_hire = cursor.fetchone()['avg_time_to_hire']
        cursor.execute("SELECT estado, COUNT(*) as total FROM Postulaciones GROUP BY estado")
        funnel_data = cursor.fetchall()
        funnel = {row['estado']: row['total'] for row in funnel_data}
        total_aplicaciones = sum(funnel.values())
        conversion_rates = {}
        if total_aplicaciones > 0:
            for estado, total in funnel.items():
                rate = (total / total_aplicaciones) * 100
                conversion_rates[estado] = round(rate, 2)
        return jsonify({
            "success": True,
            "kpis": {
                "avgTimeToFillDays": round(time_to_fill, 1) if time_to_fill else 0,
                "avgTimeToHireDays": round(time_to_hire, 1) if time_to_hire else 0,
                "conversionFunnelRaw": funnel,
                "conversionFunnelPercentage": conversion_rates
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


def _internal_search_candidates(term=None, tags=None, experience=None, city=None, recency_days=None, registered_today=False):
    """Lógica de búsqueda interna que puede ser llamada desde la API o el Asistente."""
    conn = get_db_connection()
    if not conn: return {"error": "Error de conexión"}
    cursor = conn.cursor(dictionary=True)
    try:
        base_query = """
            SELECT a.*, 
                   (SELECT GROUP_CONCAT(DISTINCT c.empresa SEPARATOR ', ') 
                    FROM Postulaciones p 
                    JOIN Vacantes v ON p.id_vacante = v.id_vacante 
                    JOIN Clientes c ON v.id_cliente = c.id_cliente 
                    WHERE p.id_afiliado = a.id_afiliado) as historialEmpresas,
                   (SELECT GROUP_CONCAT(t.nombre_tag SEPARATOR ', ') 
                    FROM Afiliado_Tags at 
                    JOIN Tags t ON at.id_tag = t.id_tag 
                    WHERE at.id_afiliado = a.id_afiliado) as tags 
            FROM Afiliados a
        """
        conditions = []
        params = []

        if term:
            if term.isdigit():
                conditions.append("(a.nombre_completo LIKE %s OR a.experiencia LIKE %s OR a.ciudad LIKE %s OR a.id_afiliado = %s OR a.identidad = %s)")
                params.extend([f"%{term}%", f"%{term}%", f"%{term}%", term, term.replace('-', '')])
            else:
                search_terms = term.split()
                for t in search_terms:
                    conditions.append("(a.nombre_completo LIKE %s OR a.experiencia LIKE %s OR a.ciudad LIKE %s OR a.grado_academico LIKE %s)")
                    params.extend([f"%{t}%", f"%{t}%", f"%{t}%", f"%{t}%"])
        
        if experience:
            conditions.append("a.experiencia LIKE %s")
            params.append(f"%{experience}%")
        if city:
            conditions.append("a.ciudad LIKE %s")
            params.append(f"%{city}%")
        if recency_days and str(recency_days).isdigit():
            conditions.append("a.fecha_registro >= CURDATE() - INTERVAL %s DAY")
            params.append(int(recency_days))
        
        # ✨ NUEVA CONDICIÓN AÑADIDA AQUÍ
        if registered_today:
            conditions.append("DATE(a.fecha_registro) = CURDATE()")

        if tags:
            tag_list = [int(t) for t in tags.split(',') if t.isdigit()]
            if tag_list:
                conditions.append("a.id_afiliado IN (SELECT at.id_afiliado FROM Afiliado_Tags at WHERE at.id_tag IN ({}) GROUP BY at.id_afiliado HAVING COUNT(DISTINCT at.id_tag) = %s)".format(','.join(['%s'] * len(tag_list))))
                params.extend(tag_list)
                params.append(len(tag_list))

        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)
        
        base_query += " ORDER BY a.fecha_registro DESC;"
        
        cursor.execute(base_query, tuple(params))
        results = cursor.fetchall()
        
        for row in results:
            for key, value in row.items():
                if isinstance(value, datetime):
                    row[key] = value.isoformat()

        return results
    except Exception as e: 
        app.logger.error(f"Error en _internal_search_candidates: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return {"error": str(e)}
    finally: 
        cursor.close()
        conn.close()



def search_candidates_tool(term=None, tags=None, experience=None, city=None, recency_days=None):
    """Herramienta para el Asistente: Busca candidatos y devuelve los resultados en formato JSON."""
    app.logger.info(f"Búsqueda de candidatos con: term={term}, tags={tags}, experience={experience}, city={city}")
    results = _internal_search_candidates(term, tags, experience, city, recency_days)
    return json.dumps(results)




# ===============================================================
# SECCIÓN DE REPORTES AVANZADOS
# ===============================================================


@app.route('/api/reports', methods=['GET'])
@token_required
def get_reports():
    report_name = request.args.get('name')
    if not report_name:
        return jsonify({"error": "Se requiere el nombre del reporte"}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    
    results = []
    sql = ""

    try:
        # --- Reporte 1: Vacantes Activas ---
        if report_name == 'vacantes_activas':
            sql = """
                SELECT 
                    v.id_vacante, v.cargo_solicitado, v.fecha_apertura, c.empresa,
                    (SELECT COUNT(*) FROM Postulaciones p WHERE p.id_vacante = v.id_vacante) as total_postulaciones,
                    (SELECT COUNT(*) FROM Entrevistas e JOIN Postulaciones p ON e.id_postulacion = p.id_postulacion WHERE p.id_vacante = v.id_vacante) as total_entrevistas,
                    DATEDIFF(CURDATE(), v.fecha_apertura) as dias_abierta
                FROM Vacantes v
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE v.estado = 'Abierta'
                ORDER BY v.fecha_apertura DESC;
            """
        # --- Reporte 2: Postulaciones Recientes (Últimos 7 días) ---
        elif report_name == 'postulaciones_recientes':
            sql = """
                SELECT a.nombre_completo, v.cargo_solicitado, p.fecha_aplicacion, p.estado
                FROM Postulaciones p
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                WHERE p.fecha_aplicacion >= CURDATE() - INTERVAL 7 DAY
                ORDER BY p.fecha_aplicacion DESC;
            """
        # --- Reporte 3: Entrevistas Agendadas (Hoy y futuro) ---
        elif report_name == 'entrevistas_agendadas':
            sql = """
                SELECT e.fecha_hora, a.nombre_completo, v.cargo_solicitado, c.empresa, e.entrevistador
                FROM Entrevistas e
                JOIN Postulaciones p ON e.id_postulacion = p.id_postulacion
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE DATE(e.fecha_hora) >= CURDATE() AND e.resultado = 'Programada'
                ORDER BY e.fecha_hora ASC;
            """
        # --- Reporte 4: Contrataciones Recientes (Últimos 30 días) ---
        elif report_name == 'contrataciones_realizadas':
            sql = """
                SELECT co.fecha_contratacion, c.empresa, v.cargo_solicitado, a.nombre_completo, (co.tarifa_servicio - co.monto_pagado) AS saldo_pendiente
                FROM Contratados co
                JOIN Vacantes v ON co.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                JOIN Afiliados a ON co.id_afiliado = a.id_afiliado
                WHERE co.fecha_contratacion >= CURDATE() - INTERVAL 30 DAY
                ORDER BY co.fecha_contratacion DESC;
            """
        # --- Reporte 5: Resumen por Cliente ---
        elif report_name == 'resumen_por_cliente':
            sql = """
                SELECT 
                    c.empresa,
                    COUNT(DISTINCT v.id_vacante) as total_vacantes,
                    SUM(CASE WHEN v.estado = 'Abierta' THEN 1 ELSE 0 END) as vacantes_abiertas,
                    (SELECT COUNT(*) FROM Contratados co JOIN Vacantes vac ON co.id_vacante = vac.id_vacante WHERE vac.id_cliente = c.id_cliente) as total_contratados,
                    (SELECT SUM(tarifa_servicio - monto_pagado) FROM Contratados co JOIN Vacantes vac ON co.id_vacante = vac.id_vacante WHERE vac.id_cliente = c.id_cliente) as total_pendiente
                FROM Clientes c
                LEFT JOIN Vacantes v ON c.id_cliente = v.id_cliente
                GROUP BY c.id_cliente
                ORDER BY total_vacantes DESC;
            """
        # --- Reporte 6: Afiliados Inactivos (Sin postular en 90 días) ---
        elif report_name == 'afiliados_inactivos':
            sql = """
                SELECT a.nombre_completo, a.telefono, a.experiencia, MAX(p.fecha_aplicacion) as ultima_postulacion
                FROM Afiliados a
                LEFT JOIN Postulaciones p ON a.id_afiliado = p.id_afiliado
                GROUP BY a.id_afiliado
                HAVING ultima_postulacion < CURDATE() - INTERVAL 90 DAY OR ultima_postulacion IS NULL
                ORDER BY ultima_postulacion ASC;
            """
        # --- Reporte 7: Vacantes sin Movimiento (Sin postulaciones en 7 días) ---
        elif report_name == 'vacantes_sin_movimiento':
            sql = """
                SELECT v.id_vacante, v.cargo_solicitado, c.empresa, v.fecha_apertura,
                       (SELECT MAX(p.fecha_aplicacion) FROM Postulaciones p WHERE p.id_vacante = v.id_vacante) AS ultima_postulacion
                FROM Vacantes v
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE v.estado = 'Abierta'
                HAVING ultima_postulacion IS NULL OR DATEDIFF(CURDATE(), ultima_postulacion) > 7
                ORDER BY ultima_postulacion ASC;
            """
        # --- Reporte 8: Candidatos con Postulaciones sin Éxito (>3 postulaciones, 0 contrataciones) ---
        elif report_name == 'candidatos_sin_exito':
            sql = """
                SELECT 
                    co.id_contratado, a.nombre_completo, c.empresa, v.cargo_solicitado, co.fecha_contratacion,
                    co.tarifa_servicio, co.monto_pagado, (co.tarifa_servicio - co.monto_pagado) AS saldo_pendiente
                FROM Contratados co
                JOIN Afiliados a ON co.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON co.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE (co.tarifa_servicio - co.monto_pagado) > 0
                ORDER BY saldo_pendiente DESC;
            """
             
        # --- Reporte 9: Pagos Pendientes por Cliente ---
        elif report_name == 'pagos_pendientes':
            sql = """
                SELECT co.id_contratado, c.empresa, v.cargo_solicitado, co.fecha_contratacion,
                       co.tarifa_servicio, co.monto_pagado, (co.tarifa_servicio - co.monto_pagado) AS saldo_pendiente
                FROM Contratados co
                JOIN Vacantes v ON co.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE (co.tarifa_servicio - co.monto_pagado) > 0
                ORDER BY saldo_pendiente DESC;
            """
        # --- Reporte 10: Tiempos Promedio (KPIs) ---
        elif report_name == 'tiempos_promedio':
            sql = """
                SELECT 
                    AVG(DATEDIFF(fecha_cierre, fecha_apertura)) as avg_dias_en_cerrar,
                    (SELECT AVG(DATEDIFF(c.fecha_contratacion, p.fecha_aplicacion)) 
                     FROM Contratados c 
                     JOIN Postulaciones p ON c.id_afiliado = p.id_afiliado AND c.id_vacante = p.id_vacante) as avg_dias_en_contratar
                FROM Vacantes 
                WHERE estado = 'Cerrada';
            """
        # --- Reporte 11: Afiliados Nuevos (Últimos 7 días) ---
        elif report_name == 'afiliados_nuevos':
            sql = """
                SELECT nombre_completo, telefono, email, ciudad, fecha_registro
                FROM Afiliados
                WHERE fecha_registro >= CURDATE() - INTERVAL 7 DAY
                ORDER BY fecha_registro DESC;
            """
        # --- Reporte 12: Clientes Inactivos (Sin vacantes nuevas en 90 días) ---
        elif report_name == 'clientes_inactivos':
            sql = """
                SELECT c.empresa, c.contacto_nombre, c.telefono, MAX(v.fecha_apertura) as ultima_vacante
                FROM Clientes c
                LEFT JOIN Vacantes v ON c.id_cliente = v.id_cliente
                GROUP BY c.id_cliente
                HAVING ultima_vacante < CURDATE() - INTERVAL 90 DAY OR ultima_vacante IS NULL
                ORDER BY ultima_vacante ASC;
            """
        # --- Reporte 13: Indicadores Mensuales (KPIs) ---
        elif report_name == 'indicadores_mensuales':
            sql = """
                SELECT
                    (SELECT COUNT(*) FROM Postulaciones WHERE MONTH(fecha_aplicacion) = MONTH(CURDATE()) AND YEAR(fecha_aplicacion) = YEAR(CURDATE())) as postulaciones_mes,
                    (SELECT COUNT(*) FROM Entrevistas WHERE MONTH(fecha_hora) = MONTH(CURDATE()) AND YEAR(fecha_hora) = YEAR(CURDATE())) as entrevistas_mes,
                    (SELECT COUNT(*) FROM Contratados WHERE MONTH(fecha_contratacion) = MONTH(CURDATE()) AND YEAR(fecha_contratacion) = YEAR(CURDATE())) as contrataciones_mes,
                    (SELECT SUM(monto_pagado) FROM Contratados WHERE MONTH(fecha_contratacion) = MONTH(CURDATE()) AND YEAR(fecha_contratacion) = YEAR(CURDATE())) as ingresos_mes;
            """
        # --- Reporte 14: Entrevistas Pendientes de Decisión ---
        elif report_name == 'entrevistas_pendientes_decision':
            sql = """
                SELECT a.nombre_completo, v.cargo_solicitado, e.fecha_hora, e.entrevistador
                FROM Entrevistas e
                JOIN Postulaciones p ON e.id_postulacion = p.id_postulacion
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                WHERE e.resultado = 'Programada' AND DATE(e.fecha_hora) < CURDATE()
                ORDER BY e.fecha_hora ASC;
            """
        else:
            return jsonify({"error": f"El reporte '{report_name}' no está definido."}), 404

        cursor.execute(sql)
        results = cursor.fetchall()
        
        for row in results:
            for key, value in row.items():
                if isinstance(value, (datetime, date)):
                    row[key] = value.isoformat()
                elif isinstance(value, timedelta):
                    row[key] = str(value)
                elif isinstance(value, Decimal):
                    row[key] = float(value)

        return jsonify({"report_name": report_name, "data": results})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Error al generar el reporte: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()





# ===============================================================
# SECCIÓN 6: ENDPOINTS PRINCIPALES (CRUDs Y BÚSQUEDAS)
# ===============================================================
@app.route('/api/dashboard', methods=['GET'])
@token_required
def get_dashboard_data():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) as total FROM Entrevistas WHERE fecha_hora >= CURDATE()")
        entrevistas_pendientes = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as total FROM Entrevistas WHERE fecha_hora < CURDATE() AND resultado = 'Programada'")
        entrevistas_sin_resultado = cursor.fetchone()['total']
        cursor.execute("SELECT V.cargo_solicitado, C.empresa, COUNT(P.id_postulacion) as postulantes FROM Postulaciones P JOIN Vacantes V ON P.id_vacante = V.id_vacante JOIN Clientes C ON V.id_cliente = C.id_cliente GROUP BY V.id_vacante, V.cargo_solicitado, C.empresa ORDER BY postulantes DESC")
        estadisticas_vacantes = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) as total FROM Afiliados WHERE DATE(fecha_registro) = CURDATE()")
        afiliados_hoy = cursor.fetchone()['total']
        cursor.execute("SELECT COUNT(*) as total FROM Afiliados WHERE MONTH(fecha_registro) = MONTH(CURDATE()) AND YEAR(fecha_registro) = YEAR(CURDATE())")
        afiliados_mes = cursor.fetchone()['total']
        cursor.execute("SELECT ciudad, COUNT(*) as total FROM Afiliados WHERE ciudad IS NOT NULL AND ciudad != '' GROUP BY ciudad ORDER BY total DESC LIMIT 5")
        top_ciudades = cursor.fetchall()
        return jsonify({
            "success": True, "entrevistasPendientes": entrevistas_pendientes,
            "entrevistasSinResultado": entrevistas_sin_resultado,
            "vacantesMasPostuladas": estadisticas_vacantes[:5],
            "vacantesMenosPostuladas": sorted(estadisticas_vacantes, key=lambda x: x['postulantes'])[:5],
            "afiliadosHoy": afiliados_hoy, "afiliadosEsteMes": afiliados_mes,
            "topCiudades": top_ciudades
        })
    except Exception as e: return jsonify({"success": False, "error": str(e)}), 500
    finally: cursor.close(); conn.close()


@app.route('/api/candidates/search', methods=['GET'])
@token_required
def search_candidates():
    """Ruta web que llama a la función de búsqueda interna, pasando los filtros desde la URL."""
    try:
        # Obtener parámetros de la URL
        term = request.args.get('q', '').strip()
        tags = request.args.get('tags', '') 
        # ✨ NUEVO PARÁMETRO
        registered_today = request.args.get('registered_today', 'false').lower() == 'true'
        
        # Llamar a la función interna con los argumentos de la URL
        results = _internal_search_candidates(term=term, tags=tags, registered_today=registered_today)
        
        if "error" in results:
            return jsonify(results), 500
            
        return jsonify(results)
        
    except Exception as e: 
        return jsonify({"error": str(e)}), 500


# ✨ SOLUCIÓN: Creamos el endpoint que faltaba
@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications():
    """
    Devuelve notificaciones para el panel de control del CRM.
    POR AHORA: Devuelve una lista vacía para evitar errores 404.
    FUTURO: Aquí puedes implementar la lógica para leer notificaciones de la BD.
    """
    try:
        # Lógica futura para obtener notificaciones...
        # Por ahora, simplemente retornamos una lista vacía con un status 200 OK.
        return jsonify([])
    except Exception as e:
        app.logger.error(f"Error en get_notifications: {e}")
        return jsonify({"error": "Error al obtener notificaciones"}), 500





@app.route('/api/candidate/profile/<int:id_afiliado>', methods=['GET', 'PUT'])
@token_required
def handle_candidate_profile(id_afiliado):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            perfil = {"infoBasica": {}, "postulaciones": [], "entrevistas": [], "tags": []}
            cursor.execute("SELECT * FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (id_afiliado, tenant_id))
            perfil['infoBasica'] = cursor.fetchone()
            if not perfil['infoBasica']: return jsonify({"error": "Candidato no encontrado"}), 404
            
            cursor.execute("""
                SELECT P.id_postulacion, P.id_vacante, P.id_afiliado, P.fecha_aplicacion, P.estado, P.comentarios, V.cargo_solicitado, C.empresa 
                FROM Postulaciones P 
                JOIN Vacantes V ON P.id_vacante = V.id_vacante 
                JOIN Clientes C ON V.id_cliente = C.id_cliente 
                WHERE P.id_afiliado = %s AND P.id_cliente = %s
            """, (id_afiliado, tenant_id))
            perfil['postulaciones'] = cursor.fetchall()
            
            cursor.execute("""
                SELECT E.*, V.cargo_solicitado, C.empresa, P.id_afiliado 
                FROM Entrevistas E 
                JOIN Postulaciones P ON E.id_postulacion = P.id_postulacion 
                JOIN Vacantes V ON P.id_vacante = V.id_vacante 
                JOIN Clientes C ON V.id_cliente = C.id_cliente 
                WHERE P.id_afiliado = %s AND E.id_cliente = %s
            """, (id_afiliado, tenant_id))
            perfil['entrevistas'] = cursor.fetchall()
            
            cursor.execute("""
                SELECT T.id_tag, T.nombre_tag 
                FROM Afiliado_Tags AT 
                JOIN Tags T ON AT.id_tag = T.id_tag 
                WHERE AT.id_afiliado = %s AND T.id_cliente = %s
            """, (id_afiliado, tenant_id))
            perfil['tags'] = cursor.fetchall()
            return jsonify(perfil)
            
        elif request.method == 'PUT':
            data = request.get_json()
            update_fields = []
            params = []
            allowed_fields = ['nombre_completo', 'telefono', 'email', 'experiencia', 'ciudad', 'grado_academico', 'observaciones']
            for field in allowed_fields:
                if field in data:
                    update_fields.append(f"{field} = %s")
                    params.append(data[field])

            if not update_fields:
                return jsonify({"error": "No se proporcionaron campos para actualizar."}), 400

            params.extend([id_afiliado, tenant_id])
            sql = f"UPDATE Afiliados SET {', '.join(update_fields)} WHERE id_afiliado = %s AND id_cliente = %s"
            cursor.execute(sql, tuple(params))
            conn.commit()
            return jsonify({"success": True, "message": "Perfil actualizado."})

    except Exception as e: return jsonify({"error": str(e)}), 500
    finally: cursor.close(); conn.close()

@app.route('/api/vacancies', methods=['GET', 'POST'])
@token_required
def handle_vacancies():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT V.*, C.empresa FROM Vacantes V JOIN Clientes C ON V.id_cliente = C.id_cliente WHERE V.id_cliente = %s ORDER BY V.fecha_apertura DESC", (tenant_id,))
            return jsonify(cursor.fetchall())
        elif request.method == 'POST':
            data = request.get_json()
            sql = "INSERT INTO Vacantes (id_cliente, cargo_solicitado, ciudad, requisitos, salario, fecha_apertura, estado) VALUES (%s, %s, %s, %s, %s, CURDATE(), 'Abierta')"
            cursor.execute(sql, (tenant_id, data['cargo_solicitado'], data['ciudad'], data['requisitos'], data.get('salario')))
            conn.commit()
            return jsonify({"success": True, "message": "Vacante creada."}), 201
    except Exception as e: conn.rollback(); return jsonify({"error": str(e)}), 500
    finally: cursor.close(); conn.close()

@app.route('/api/vacancies/<int:id_vacante>/status', methods=['PUT'])
@token_required
def update_vacancy_status(id_vacante):
    data = request.get_json()
    nuevo_estado = data.get('estado')
    if not nuevo_estado: return jsonify({"error": "El nuevo estado es requerido"}), 400
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        if nuevo_estado.lower() == 'cerrada':
            cursor.execute("UPDATE Vacantes SET estado = %s, fecha_cierre = CURDATE() WHERE id_vacante = %s", (nuevo_estado, id_vacante))
        else:
            cursor.execute("UPDATE Vacantes SET estado = %s WHERE id_vacante = %s", (nuevo_estado, id_vacante))
        conn.commit()
        return jsonify({"success": True, "message": f"Vacante actualizada a {nuevo_estado}."})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/vacancies/active', methods=['GET'])
@token_required
def get_active_vacancies():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT V.id_vacante, V.cargo_solicitado, C.empresa FROM Vacantes V JOIN Clientes C ON V.id_cliente = C.id_cliente WHERE V.estado = 'Abierta'")
        vacantes = [{"id": v['id_vacante'], "puesto": f"{v['cargo_solicitado']} - {v['empresa']}"} for v in cursor.fetchall()]
        return jsonify(vacantes)
    except Exception as e: return jsonify({"error": str(e)}), 500
    finally: cursor.close(); conn.close()

# En app.py, reemplaza esta función completa
@app.route('/api/applications', methods=['GET','POST'])
@token_required
def handle_applications():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'GET':
            tenant_id = get_current_tenant_id()
            base_sql = """
                SELECT p.id_postulacion, p.id_afiliado, p.fecha_aplicacion, p.estado, p.comentarios,
                       p.whatsapp_notification_status, a.nombre_completo, a.cv_url, 
                       v.cargo_solicitado, c.empresa, v.ciudad
                FROM Postulaciones p
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE p.id_cliente = %s
            """
            conditions = []
            params = [tenant_id]
            if request.args.get('vacante_id'):
                conditions.append("p.id_vacante = %s")
                params.append(request.args.get('vacante_id'))
            if request.args.get('estado'):
                conditions.append("p.estado = %s")
                params.append(request.args.get('estado'))
            if request.args.get('fecha_inicio'):
                conditions.append("p.fecha_aplicacion >= %s")
                params.append(request.args.get('fecha_inicio'))
            if conditions:
                base_sql += " AND " + " AND ".join(conditions)
            base_sql += " ORDER BY p.fecha_aplicacion DESC"
            cursor.execute(base_sql, tuple(params))
            # Convertir fechas para que sean compatibles con JSON
            results = cursor.fetchall()
            for row in results:
                for key, value in row.items():
                    if isinstance(value, (datetime, date)):
                        row[key] = value.isoformat()
            return jsonify(results)
        
        elif request.method == 'POST':
            data = request.get_json()
            tenant_id = get_current_tenant_id()
            
            # Verificar que el afiliado y la vacante pertenecen al tenant
            cursor.execute("SELECT id_afiliado FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (data['id_afiliado'], tenant_id))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Afiliado no encontrado"}), 404
                
            cursor.execute("SELECT id_vacante FROM Vacantes WHERE id_vacante = %s AND id_cliente = %s", (data['id_vacante'], tenant_id))
            if not cursor.fetchone():
                return jsonify({"success": False, "message": "Vacante no encontrada"}), 404
            
            cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_afiliado = %s AND id_vacante = %s AND id_cliente = %s", (data['id_afiliado'], data['id_vacante'], tenant_id))
            if cursor.fetchone(): return jsonify({"success": False, "message": "Este candidato ya ha postulado a esta vacante."}), 409
            
            sql = "INSERT INTO Postulaciones (id_afiliado, id_vacante, fecha_aplicacion, estado, comentarios, id_cliente) VALUES (%s, %s, NOW(), 'Recibida', %s, %s)"
            cursor.execute(sql, (data['id_afiliado'], data['id_vacante'], data.get('comentarios', ''), tenant_id))
            new_postulation_id = cursor.lastrowid
            conn.commit()

            cursor.execute("""
                SELECT a.telefono, a.nombre_completo, v.cargo_solicitado, v.ciudad, v.salario, v.requisitos
                FROM Afiliados a, Vacantes v WHERE a.id_afiliado = %s AND v.id_vacante = %s
            """, (data['id_afiliado'], data['id_vacante']))
            info = cursor.fetchone()

            if info and info.get('telefono'):
                # Convertir Decimal a float si existe
                salario_val = info.get('salario')
                salario_str = f"L. {float(salario_val):,.2f}" if salario_val else "No especificado"
                message_body = (
                    f"¡Hola {info['nombre_completo'].split(' ')[0]}! Te saluda Henmir. 👋\n\n"
                    f"Hemos considerado tu perfil para una nueva oportunidad laboral y te hemos postulado a la siguiente vacante:\n\n"
                    f"📌 *Puesto:* {info['cargo_solicitado']}\n"
                    f"📍 *Ubicación:* {info['ciudad']}\n"
                    f"💰 *Salario:* {salario_str}\n\n"
                    f"*Requisitos principales:*\n{info['requisitos']}\n\n"
                    "Por favor, confirma si estás interesado/a en continuar con este proceso. ¡Mucho éxito!"
                )
                
                # Enviar tarea asíncrona a Celery
                task = send_whatsapp_notification_task.delay(
                    task_type="postulation",
                    related_id=new_postulation_id,
                    phone_number=info['telefono'],
                    message_body=message_body,
                    candidate_name=info['nombre_completo']
                )
                
                return jsonify({
                    "success": True, 
                    "message": "Postulación registrada exitosamente. Notificación WhatsApp en proceso.", 
                    "id_postulacion": new_postulation_id,
                    "task_id": task.id,
                    "notification_status": "processing"
                }), 201
            
            return jsonify({"success": True, "message": "Postulación registrada (candidato sin teléfono para notificar).", "id_postulacion": new_postulation_id}), 201
            
    except Exception as e: 
        conn.rollback(); import traceback; traceback.print_exc(); return jsonify({"success": False, "error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()


@app.route('/api/applications/<int:id_postulacion>', methods=['DELETE'])
@token_required
def delete_application(id_postulacion):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        tenant_id = get_current_tenant_id()
        
        # Verificar que la postulación pertenece al tenant
        cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (id_postulacion, tenant_id))
        if not cursor.fetchone():
            return jsonify({"success": False, "error": "Postulación no encontrada."}), 404
        
        # Antes de borrar la postulación, borramos las entrevistas asociadas si existen
        cursor.execute("DELETE FROM Entrevistas WHERE id_postulacion = %s", (id_postulacion,))
        
        # Ahora borramos la postulación
        cursor.execute("DELETE FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (id_postulacion, tenant_id))
        
        conn.commit()
        return jsonify({"success": True, "message": "Postulación eliminada correctamente."})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# AÑADE esta nueva función justo después de 'delete_application' en app.py

@app.route('/api/applications/<int:id_postulacion>/comments', methods=['PUT'])
@token_required
def update_application_comments(id_postulacion):
    data = request.get_json()
    nuevos_comentarios = data.get('comentarios', '') # Aceptamos comentarios vacíos

    if 'comentarios' not in data:
        return jsonify({"success": False, "error": "El campo 'comentarios' es requerido."}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        sql = "UPDATE Postulaciones SET comentarios = %s WHERE id_postulacion = %s"
        cursor.execute(sql, (nuevos_comentarios, id_postulacion))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({"success": False, "error": f"No se encontró una postulación con el ID {id_postulacion}."}), 404

        conn.commit()
        return jsonify({"success": True, "message": "Comentarios de la postulación actualizados."})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": f"Error inesperado al actualizar comentarios: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()



# En app.py, reemplaza esta función completa
@app.route('/api/interviews', methods=['GET', 'POST'])
@token_required
def handle_interviews():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            sql = """
                SELECT e.id_entrevista, e.fecha_hora, e.entrevistador, e.resultado, e.observaciones,
                       p.id_afiliado, a.nombre_completo, v.cargo_solicitado, v.id_vacante, c.empresa
                FROM Entrevistas e
                JOIN Postulaciones p ON e.id_postulacion = p.id_postulacion
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE e.id_cliente = %s
            """
            conditions = []
            params = [tenant_id]
            if request.args.get('vacante_id'):
                conditions.append("v.id_vacante = %s")
                params.append(request.args.get('vacante_id'))
            if conditions:
                sql += " AND " + " AND ".join(conditions)
            sql += " ORDER BY e.fecha_hora DESC"
            cursor.execute(sql, tuple(params))
            results = cursor.fetchall()
            for row in results:
                if isinstance(row.get('fecha_hora'), (datetime, date)):
                    row['fecha_hora'] = row['fecha_hora'].isoformat()
            return jsonify(results)

        elif request.method == 'POST':
            data = request.get_json()
            id_postulacion = data.get('id_postulacion')
            fecha_hora_str = data.get('fecha_hora')
            entrevistador = data.get('entrevistador')
            observaciones = data.get('observaciones', '')

            if not all([id_postulacion, fecha_hora_str, entrevistador]):
                return jsonify({"success": False, "error": "Faltan datos requeridos."}), 400

            try:
                # Verificar que la postulación pertenece al tenant
                cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (id_postulacion, tenant_id))
                if not cursor.fetchone():
                    return jsonify({"success": False, "error": "Postulación no encontrada."}), 404
                
                sql_insert = "INSERT INTO Entrevistas (id_postulacion, fecha_hora, entrevistador, resultado, observaciones, id_cliente) VALUES (%s, %s, %s, 'Programada', %s, %s)"
                cursor.execute(sql_insert, (id_postulacion, fecha_hora_str, entrevistador, observaciones, tenant_id))
                new_interview_id = cursor.lastrowid
                
                cursor.execute("UPDATE Postulaciones SET estado = 'En Entrevista' WHERE id_postulacion = %s", (id_postulacion,))
                conn.commit()

                cursor.execute("""
                    SELECT a.telefono, a.nombre_completo, v.cargo_solicitado, c.empresa FROM Postulaciones p
                    JOIN Afiliados a ON p.id_afiliado = a.id_afiliado JOIN Vacantes v ON p.id_vacante = v.id_vacante JOIN Clientes c ON v.id_cliente = c.id_cliente
                    WHERE p.id_postulacion = %s
                """, (id_postulacion,))
                info = cursor.fetchone()

                if info and info.get('telefono'):
                    fecha_obj = datetime.fromisoformat(fecha_hora_str)
                    fecha_formateada = fecha_obj.strftime('%A, %d de %B de %Y a las %I:%M %p')
                    message_body = (
                        f"¡Buenas noticias, {info['nombre_completo'].split(' ')[0]}! 🎉\n\n"
                        f"Hemos agendado tu entrevista para la vacante de *{info['cargo_solicitado']}* en la empresa *{info['empresa']}*.\n\n"
                        f"🗓️ *Fecha y Hora:* {fecha_formateada}\n👤 *Entrevistador(a):* {entrevistador}\n\n*Detalles adicionales:*\n{observaciones}\n\n"
                        "Por favor, sé puntual. ¡Te deseamos mucho éxito en tu entrevista!"
                    )
                    
                    # Enviar tarea asíncrona a Celery
                    task = send_whatsapp_notification_task.delay(
                        task_type="interview",
                        related_id=new_interview_id,
                        phone_number=info['telefono'],
                        message_body=message_body,
                        candidate_name=info['nombre_completo']
                    )
                    
                    return jsonify({
                        "success": True, 
                        "message": "Entrevista agendada exitosamente. Notificación WhatsApp en proceso.", 
                        "id_entrevista": new_interview_id,
                        "task_id": task.id,
                        "notification_status": "processing"
                    }), 201
                
                return jsonify({"success": True, "message": "Entrevista agendada."}), 201
            
            except mysql.connector.Error as err:
                conn.rollback()
                if err.errno == 1452: return jsonify({"success": False, "error": f"La postulación con ID {id_postulacion} no existe."}), 404
                return jsonify({"success": False, "error": f"Error de base de datos: {str(err)}"}), 500
            except Exception as e: 
                conn.rollback()
                return jsonify({"success": False, "error": str(e)}), 500
    finally: 
        cursor.close()
        conn.close()


@app.route('/api/hired', methods=['GET', 'POST'])
@token_required
def handle_hired():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            sql = """
                SELECT 
                    co.id_contratado, co.fecha_contratacion, co.salario_final,
                    IFNULL(co.tarifa_servicio, 0) as tarifa_servicio, 
                    IFNULL(co.monto_pagado, 0) as monto_pagado,
                    (IFNULL(co.tarifa_servicio, 0) - IFNULL(co.monto_pagado, 0)) AS saldo_pendiente,
                    a.id_afiliado, a.nombre_completo, v.cargo_solicitado, c.empresa
                FROM Contratados co
                JOIN Afiliados a ON co.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON co.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE co.id_cliente = %s
                ORDER BY saldo_pendiente DESC, co.fecha_contratacion DESC;
            """
            cursor.execute(sql, (tenant_id,))
            results = cursor.fetchall()
            for row in results:
                if isinstance(row.get('fecha_contratacion'), (datetime, date)):
                    row['fecha_contratacion'] = row['fecha_contratacion'].isoformat()
                for key, value in row.items():
                    if isinstance(value, Decimal):
                        row[key] = float(value)
            return jsonify(results)

        elif request.method == 'POST':
            data = request.get_json()
            id_afiliado = data.get('id_afiliado')
            id_vacante = data.get('id_vacante')

            if not all([id_afiliado, id_vacante]):
                 return jsonify({"success": False, "error": "Faltan id_afiliado o id_vacante."}), 400
            
            try:
                # Verificar que el afiliado y vacante pertenecen al tenant
                cursor.execute("SELECT id_afiliado FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (id_afiliado, tenant_id))
                if not cursor.fetchone():
                    return jsonify({"success": False, "error": "Afiliado no encontrado."}), 404
                
                cursor.execute("SELECT id_vacante FROM Vacantes WHERE id_vacante = %s AND id_cliente = %s", (id_vacante, tenant_id))
                if not cursor.fetchone():
                    return jsonify({"success": False, "error": "Vacante no encontrada."}), 404
                
                sql_insert = "INSERT INTO Contratados (id_afiliado, id_vacante, fecha_contratacion, salario_final, tarifa_servicio, id_cliente) VALUES (%s, %s, CURDATE(), %s, %s, %s)"
                cursor.execute(sql_insert, (id_afiliado, id_vacante, data.get('salario_final'), data.get('tarifa_servicio'), tenant_id))
                new_hired_id = cursor.lastrowid
                
                cursor.execute("UPDATE Postulaciones SET estado = 'Contratado' WHERE id_afiliado = %s AND id_vacante = %s AND id_cliente = %s", (id_afiliado, id_vacante, tenant_id))
                conn.commit()

                cursor.execute("""
                    SELECT a.telefono, a.nombre_completo, v.cargo_solicitado, c.empresa
                    FROM Afiliados a, Vacantes v, Clientes c
                    WHERE a.id_afiliado = %s AND v.id_vacante = %s AND v.id_cliente = c.id_cliente
                """, (id_afiliado, id_vacante))
                info = cursor.fetchone()

                if info and info.get('telefono'):
                    message_body = (
                        f"¡FELICIDADES, {info['nombre_completo'].split(' ')[0]}! 🥳\n\n"
                        f"Nos complace enormemente informarte que has sido **CONTRATADO/A** para el puesto de *{info['cargo_solicitado']}* en la empresa *{info['empresa']}*.\n\n"
                        "Este es un gran logro y el resultado de tu excelente desempeño en el proceso de selección. En breve, el equipo de recursos humanos de la empresa se pondrá en contacto contigo para coordinar los siguientes pasos.\n\n"
                        "De parte de todo el equipo de Henmir, ¡te deseamos el mayor de los éxitos en tu nuevo rol!"
                    )
                    
                    # Enviar tarea asíncrona a Celery
                    task = send_whatsapp_notification_task.delay(
                        task_type="hired",
                        related_id=new_hired_id,
                        phone_number=info['telefono'],
                        message_body=message_body,
                        candidate_name=info['nombre_completo']
                    )
                    
                    return jsonify({
                        "success": True, 
                        "message": "Candidato contratado exitosamente. Notificación WhatsApp en proceso.", 
                        "id_contratado": new_hired_id,
                        "task_id": task.id,
                        "notification_status": "processing"
                    }), 201

                return jsonify({"success": True, "message": "Candidato registrado como contratado."}), 201

            except mysql.connector.Error as err:
                conn.rollback()
                if err.errno == 1062: return jsonify({"success": False, "error": "Este candidato ya ha sido registrado como contratado para esta vacante."}), 409
                return jsonify({"success": False, "error": f"Error de base de datos: {str(err)}"}), 500
            except Exception as e: 
                conn.rollback()
                return jsonify({"success": False, "error": str(e)}), 500    
    finally: 
        cursor.close()
        conn.close()

@app.route('/api/hired/<int:id_contratado>/payment', methods=['POST'])
@token_required
def register_payment(id_contratado):
    data = request.get_json()
    monto_pago = data.get('monto')

    if not monto_pago:
        return jsonify({"success": False, "error": "El monto del pago es requerido."}), 400
    
    try:
        monto_float = float(monto_pago)
        if monto_float <= 0:
            return jsonify({"success": False, "error": "El monto del pago debe ser un número positivo."}), 400
    except (ValueError, TypeError):
        return jsonify({"success": False, "error": "El monto del pago debe ser un número válido."}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        tenant_id = get_current_tenant_id()
        
        # Usamos una actualización atómica para evitar problemas de concurrencia
        sql = "UPDATE Contratados SET monto_pagado = monto_pagado + %s WHERE id_contratado = %s AND id_cliente = %s"
        cursor.execute(sql, (monto_float, id_contratado, tenant_id))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"success": False, "error": "No se encontró el registro de contratación."}), 404

        return jsonify({"success": True, "message": "Pago registrado correctamente."})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()




@app.route('/api/hired/<int:id_contratado>', methods=['DELETE'])
@token_required
def annul_hiring(id_contratado):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        # Primero, obtenemos los IDs necesarios antes de borrar
        cursor.execute("SELECT id_afiliado, id_vacante FROM Contratados WHERE id_contratado = %s AND id_cliente = %s", (id_contratado, tenant_id))
        record = cursor.fetchone()
        if not record:
            return jsonify({"success": False, "error": "Registro de contratación no encontrado."}), 404

        # Segundo, borramos el registro de la tabla Contratados
        cursor.execute("DELETE FROM Contratados WHERE id_contratado = %s AND id_cliente = %s", (id_contratado, tenant_id))
        
        # Tercero, revertimos el estado de la postulación a 'Oferta' o el estado anterior que consideres
        cursor.execute("UPDATE Postulaciones SET estado = 'Oferta' WHERE id_afiliado = %s AND id_vacante = %s AND id_cliente = %s", (record['id_afiliado'], record['id_vacante'], tenant_id))
        
        conn.commit()
        return jsonify({"success": True, "message": "Contratación anulada correctamente."})
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()




@app.route('/api/clients', methods=['GET', 'POST'])
@token_required
def handle_clients():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Clientes ORDER BY empresa")
            return jsonify(cursor.fetchall())
        elif request.method == 'POST':
            data = request.get_json()
            sql = "INSERT INTO Clientes (empresa, contacto_nombre, telefono, email, sector, observaciones) VALUES (%s, %s, %s, %s, %s, %s)"
            cursor.execute(sql, (data['empresa'], data['contacto_nombre'], data['telefono'], data['email'], data['sector'], data['observaciones']))
            conn.commit()
            return jsonify({"success": True, "message": "Cliente agregado."}), 201
    except Exception as e: conn.rollback(); return jsonify({"success": False, "error": str(e)}), 500
    finally: cursor.close(); conn.close()

# ===============================================================
# SECCIÓN 7: LÓGICA INTERNA DEL CHATBOT
# ===============================================================

def get_chatbot_settings():
    """Lee la configuración del chatbot desde la tabla Chatbot_Settings."""
    conn = get_db_connection()
    if not conn:
        return {"error": "No se pudo conectar a la BD para obtener la configuración."}
    
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT setting_name, setting_value FROM Chatbot_Settings")
        settings_from_db = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
        
        return {
            "system_prompt": settings_from_db.get('system_prompt', 'ERROR: Prompt no configurado.'),
            "model": settings_from_db.get('chatbot_model', 'gpt-4o-mini'),
            "temperature": float(settings_from_db.get('chatbot_temperature', 0.7))
        }
    except Exception as e:
        app.logger.error(f"Error al leer la configuración del chatbot: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return {"error": str(e)}
    finally:
        cursor.close()
        conn.close()


# ===============================================================
# SECCIÓN 8: API DE HERRAMIENTAS PARA EL CHATBOT EXTERNO
# ===============================================================


@app.route('/api/bot_tools/vacancies', methods=['GET'])
@require_api_key
def bot_get_vacancies():
    """Endpoint seguro para que el bot de Node.js consulte vacantes."""
    city = request.args.get('city')
    keyword = request.args.get('keyword')
    app.logger.info("INICIANDO BÚSQUEDA DE VACANTES PARA BOT")
    app.logger.info(f"Parámetros recibidos: ciudad='{city}', palabra_clave='{keyword}'")
    
    conn = get_db_connection()
    if not conn: 
        app.logger.error("ERROR: Fallo en la conexión a la BD en bot_get_vacancies")
        return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        query = "SELECT cargo_solicitado, ciudad FROM Vacantes WHERE estado = 'Abierta'"
        params = []
        
        if city:
            query += " AND LOWER(ciudad) LIKE LOWER(%s)"
            params.append(f"%{city}%")
        
        if keyword:
            query += " AND (LOWER(cargo_solicitado) LIKE LOWER(%s) OR LOWER(requisitos) LIKE LOWER(%s))"
            params.extend([f"%{keyword}%", f"%{keyword}%"])
        
        app.logger.info(f"Ejecutando SQL: {query}")
        app.logger.info(f"Con parámetros: {params}")
        
        cursor.execute(query, tuple(params))
        results = cursor.fetchall()
        
        app.logger.info(f"SQL EJECUTADO. Número de resultados encontrados en la BD: {len(results)}")
        
        # Convertimos a JSON y lo registramos para auditoría
        response_json = json.dumps(results)
        app.logger.info(f"Respuesta JSON que se enviará a bridge.js (primeros 200 caracteres): {response_json[:200]}...")
        
        return Response(response_json, mimetype='application/json')
        
    except Exception as e:
        app.logger.error(f"ERROR crítico en bot_get_vacancies: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/api/bot_tools/validate_registration', methods=['GET'])
@require_api_key
def bot_validate_registration():
    """
    Endpoint seguro para que el bot valide si un candidato con una identidad dada
    existe en el sistema.
    """
    identity_number = request.args.get('identity') or request.args.get('identity_number')
    
    app.logger.info(f"[Herramienta Validar] Parámetros recibidos en la URL: {request.args}")

    if not identity_number:
        return jsonify({"error": "Parámetro 'identity' es requerido."}), 400
        
    clean_identity = str(identity_number).replace('-', '').strip()

    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)

    try:
        # La consulta ahora solo busca al afiliado. La existencia es el único criterio de éxito.
        query = "SELECT id_afiliado, nombre_completo FROM Afiliados WHERE identidad = %s LIMIT 1"
        cursor.execute(query, (clean_identity,))
        result = cursor.fetchone()

        if result:
            # --- LÓGICA CORREGIDA ---
            # Si se encuentra un resultado, SIEMPRE es un éxito.
            app.logger.info(f"Validación exitosa. Se encontró a {result['nombre_completo']} con identidad {clean_identity}")
            return jsonify({
                "success": True, 
                "candidate_name": result['nombre_completo'],
                "identity_verified": clean_identity # Devolvemos la identidad limpia para confirmación
            })
        else:
            # Si no se encuentra la identidad, es un fallo.
            app.logger.warning(f"Validación fallida. No se encontró candidato con identidad {clean_identity}")
            return jsonify({
                "success": False, 
                "message": "No hemos podido encontrar tu registro con esa identidad. Por favor, asegúrate de haber completado el formulario y de que el número sea correcto."
            })

    except Exception as e:
        app.logger.error(f"Error crítico en endpoint bot_validate_registration: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        

@app.route('/api/dashboard/activity_chart', methods=['GET'])
@token_required
def get_dashboard_activity():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        # Consulta para nuevos afiliados por día en los últimos 30 días
        sql_afiliados = """
            SELECT DATE(fecha_registro) as dia, COUNT(id_afiliado) as total 
            FROM Afiliados 
            WHERE fecha_registro >= CURDATE() - INTERVAL 30 DAY 
            GROUP BY DATE(fecha_registro) 
            ORDER BY dia;
        """
        cursor.execute(sql_afiliados)
        afiliados_data = cursor.fetchall()

        # Consulta para nuevas postulaciones por día en los últimos 30 días
        sql_postulaciones = """
            SELECT DATE(fecha_aplicacion) as dia, COUNT(id_postulacion) as total 
            FROM Postulaciones 
            WHERE fecha_aplicacion >= CURDATE() - INTERVAL 30 DAY 
            GROUP BY DATE(fecha_aplicacion) 
            ORDER BY dia;
        """
        cursor.execute(sql_postulaciones)
        postulaciones_data = cursor.fetchall()
        
        # Formatear fechas a string para JSON
        for row in afiliados_data: row['dia'] = row['dia'].isoformat()
        for row in postulaciones_data: row['dia'] = row['dia'].isoformat()

        return jsonify({
            "success": True, 
            "afiliados": afiliados_data, 
            "postulaciones": postulaciones_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        

@app.route('/api/bot_tools/settings', methods=['GET'])
@require_api_key
def bot_get_settings():
    """
    Endpoint seguro para que el bot de Node.js obtenga su configuración
    (prompt, modelo, etc.) desde la base de datos del CRM.
    """
    try:
        settings = get_chatbot_settings() # Reutilizamos la función que ya creamos
        return jsonify(settings)
    except Exception as e:
        return jsonify({"error": str(e)}), 500  
    
    

@app.route('/api/bot_tools/all_active_vacancies', methods=['GET'])
@require_api_key
def bot_get_all_active_vacancies():
    """
    Endpoint seguro para que el bot obtenga una lista simple de TODOS 
    los cargos de las vacantes actualmente abiertas.
    """
    app.logger.info("[Herramienta Chatbot] Solicitando lista completa de vacantes activas")
    conn = get_db_connection()
    if not conn: 
        return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT cargo_solicitado FROM Vacantes WHERE estado = 'Abierta' ORDER BY cargo_solicitado ASC"
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Devolvemos una lista simple de strings para que sea ligera
        cargo_list = [row['cargo_solicitado'] for row in results]
        
        app.logger.info(f"Encontradas {len(cargo_list)} vacantes activas en total")
        return jsonify(cargo_list)
        
    except Exception as e:
        app.logger.error(f"Error en endpoint bot_get_all_active_vacancies: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()     
        

@app.route('/api/bot_tools/vacancy_details', methods=['GET'])
@require_api_key
def bot_get_vacancy_details():
    """
    Endpoint seguro para que el bot obtenga los requisitos detallados
    de una vacante específica por su nombre.
    """
    cargo = request.args.get('cargo_solicitado')
    if not cargo:
        return jsonify({"error": "El 'cargo_solicitado' es requerido."}), 400

    app.logger.info(f"[Herramienta Chatbot] Buscando detalles para la vacante: '{cargo}'")
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Buscamos la vacante que más se parezca al cargo solicitado
        query = "SELECT cargo_solicitado, requisitos FROM Vacantes WHERE estado = 'Abierta' AND LOWER(cargo_solicitado) LIKE LOWER(%s) LIMIT 1"
        params = (f"%{cargo}%",)
        
        cursor.execute(query, params)
        result = cursor.fetchone()
        
        if result:
            app.logger.info(f"Encontrados detalles para '{result['cargo_solicitado']}'")
            return jsonify(result)
        else:
            app.logger.warning(f"No se encontraron detalles para la vacante '{cargo}'")
            return jsonify({"error": f"No se encontró una vacante llamada '{cargo}'."})
        
    except Exception as e:
        app.logger.error(f"Error en endpoint bot_get_vacancy_details: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()        
        
        
# =================================================================
# INSERTAR NUEVA FUNCIÓN (Herramienta de Estado con Confidencialidad)
# =================================================================
@app.route('/api/bot_tools/candidate_status', methods=['GET'])
@require_api_key
def bot_get_candidate_status():
    """
    Endpoint seguro para que el bot consulte todas las postulaciones
    y su estado para un candidato específico, incluyendo detalles de entrevistas si existen.
    IMPORTANTE: Este endpoint NUNCA debe devolver el nombre de la empresa.
    """
    identity_number = request.args.get('identity_number')
    if not identity_number:
        return jsonify({"error": "El 'identity_number' es requerido."}), 400

    clean_identity = str(identity_number).replace('-', '').strip()
    app.logger.info(f"[Herramienta Chatbot] Buscando estado y entrevistas para identidad: '{clean_identity}'")
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Primero, encontramos al afiliado para asegurar que existe.
        cursor.execute("SELECT id_afiliado, nombre_completo FROM Afiliados WHERE identidad = %s", (clean_identity,))
        afiliado = cursor.fetchone()

        if not afiliado:
            app.logger.warning(f"No se encontró candidato con identidad {clean_identity}")
            return jsonify({"status": "not_registered"})

        # ✨ CONSULTA MEJORADA: Hacemos un LEFT JOIN con Entrevistas para obtener sus detalles
        query = """
            SELECT 
                p.id_postulacion,
                p.fecha_aplicacion,
                p.estado,
                v.cargo_solicitado,
                e.fecha_hora AS fecha_entrevista,
                e.entrevistador,
                e.observaciones AS detalles_entrevista
            FROM Postulaciones p
            JOIN Vacantes v ON p.id_vacante = v.id_vacante
            LEFT JOIN Entrevistas e ON p.id_postulacion = e.id_postulacion
            WHERE p.id_afiliado = %s
            ORDER BY p.fecha_aplicacion DESC;
        """
        cursor.execute(query, (afiliado['id_afiliado'],))
        postulaciones = cursor.fetchall()

        # Formateamos las fechas para que sean legibles y amigables
        for post in postulaciones:
            if post.get('fecha_aplicacion'):
                post['fecha_aplicacion'] = post['fecha_aplicacion'].strftime('%d de %B de %Y')
            if post.get('fecha_entrevista'):
                # Formato: Lunes, 01 de Agosto a las 03:30 PM
                post['fecha_entrevista'] = post['fecha_entrevista'].strftime('%A, %d de %B a las %I:%M %p')

        if not postulaciones:
            app.logger.info(f"Candidato '{afiliado['nombre_completo']}' encontrado, pero sin postulaciones")
            return jsonify({
                "status": "registered_no_applications", 
                "candidate_name": afiliado['nombre_completo']
            })
        
        app.logger.info(f"Encontradas {len(postulaciones)} postulaciones para '{afiliado['nombre_completo']}'")
        return jsonify({
            "status": "has_applications",
            "candidate_name": afiliado['nombre_completo'],
            "applications": postulaciones
        })
        
    except Exception as e:
        app.logger.error(f"Error en endpoint bot_get_candidate_status: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# =================================================================
# INSERTAR NUEVO BLOQUE DE CÓDIGO AL FINAL DE LA SECCIÓN 8
# =================================================================

@app.route('/api/bot_tools/vacancies_with_details', methods=['GET'])
@require_api_key
def bot_get_vacancies_with_details():
    """
    (NUEVA HERRAMIENTA) Endpoint para que el bot obtenga detalles completos 
    (cargo, ciudad, REQUISITOS) de TODAS las vacantes activas.
    Diseñada para ser usada solo cuando el bot necesite analizar los requisitos.
    """
    app.logger.info("[Herramienta Chatbot DETALLADA] Solicitando lista completa de vacantes con requisitos")
    conn = get_db_connection()
    if not conn: 
        return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT cargo_solicitado, ciudad, requisitos FROM Vacantes WHERE estado = 'Abierta'"
        cursor.execute(query)
        results = cursor.fetchall()
        app.logger.info(f"Encontradas {len(results)} vacantes con detalles para análisis")
        return jsonify(results)
        
    except Exception as e:
        app.logger.error(f"Error en endpoint bot_get_vacancies_with_details: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/applications/update_notification_status', methods=['POST'])
@require_api_key
def update_notification_status():
    """Endpoint seguro para que bridge.js actualice el estado de una notificación."""
    data = request.get_json()
    postulation_id = data.get('postulation_id')
    status = data.get('status') # 'sent' o 'failed'

    if not all([postulation_id, status]):
        return jsonify({"error": "Faltan postulation_id o status"}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor()
    try:
        sql = "UPDATE Postulaciones SET whatsapp_notification_status = %s WHERE id_postulacion = %s"
        cursor.execute(sql, (status, postulation_id))
        conn.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/applications/resync_pending_notifications', methods=['POST'])
@require_api_key
def resync_pending_notifications():
    """Busca todas las postulaciones con notificaciones pendientes y las re-envía a bridge.js."""
    app.logger.info("INICIANDO RESINCRONIZACIÓN DE NOTIFICACIONES PENDIENTES")
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB connection failed"}), 500
    cursor = conn.cursor(dictionary=True)
    
    tasks_sent = 0
    try:
        # Solo buscamos postulaciones, las otras notificaciones son menos críticas si fallan.
        query = """
            SELECT p.id_postulacion, a.telefono, a.nombre_completo, v.cargo_solicitado, v.ciudad, v.salario, v.requisitos
            FROM Postulaciones p
            JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
            JOIN Vacantes v ON p.id_vacante = v.id_vacante
            WHERE p.whatsapp_notification_status = 'pending'
        """
        cursor.execute(query)
        pending_notifications = cursor.fetchall()

        for info in pending_notifications:
            salario_info = f"Salario: {info['salario']}" if info.get('salario') else "Salario: No especificado"
            message_body = (
                f"¡Hola {info['nombre_completo'].split(' ')[0]}! Te saluda Henmir. 👋\n\n"
                f"Hemos considerado tu perfil para una nueva oportunidad laboral y te hemos postulado a la siguiente vacante:\n\n"
                f"📌 *Puesto:* {info['cargo_solicitado']}\n"
                f"📍 *Ubicación:* {info['ciudad']}\n"
                f"💰 *{salario_info}*\n\n"
                f"*Requisitos principales:*\n{info['requisitos']}\n\n"
                "Por favor, confirma si estás interesado/a en continuar con este proceso. ¡Mucho éxito!"
            )
            task = {
                "task_type": "postulation",
                "related_id": info['id_postulacion'],
                "chat_id": clean_phone_number(info['telefono']),
                "message_body": message_body
            }
            if _send_task_to_bridge(task):
                tasks_sent += 1
        
        app.logger.info(f"Resincronización completada. {tasks_sent} tareas reenviadas a bridge.js.")
        return jsonify({"success": True, "tasks_resent": tasks_sent}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# --- FIN DEL NUEVO BLOQUE ---
# =================================================================

@app.route('/api/internal/all_affiliates_for_sync', methods=['GET'])
@require_api_key # Protegemos este endpoint para que solo nuestro bridge pueda usarlo
def get_all_affiliates_for_sync():
    """
    Endpoint interno y seguro diseñado para ser llamado únicamente por bridge.js.
    Devuelve una lista de todos los afiliados con un número de teléfono válido,
    junto con su número de identidad, para la sincronización inicial de estados.
    """
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        # Seleccionamos solo los afiliados que tienen un número de teléfono, que es esencial para el chat.
        query = "SELECT identidad, telefono FROM Afiliados WHERE telefono IS NOT NULL AND telefono != ''"
        cursor.execute(query)
        affiliates = cursor.fetchall()
        
        # Limpiamos los números de teléfono para asegurar un formato consistente
        for affiliate in affiliates:
            affiliate['telefono'] = clean_phone_number(affiliate.get('telefono'))

        app.logger.info(f"Sincronización solicitada: Se encontraron {len(affiliates)} afiliados con teléfono para enviar a bridge.js.")
        return jsonify(affiliates)
        
    except Exception as e:
        app.logger.error(f"Error en el endpoint de sincronización de afiliados: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/uploads/<path:folder>/<path:filename>')
def serve_uploaded_file(folder, filename):
    """
    Sirve los archivos guardados localmente desde el directorio /uploads.
    Esta es la ruta que permite que los enlaces a los CVs y fotos de ID funcionen.
    """
    # Medida de seguridad: solo permitir acceso a subcarpetas conocidas
    allowed_folders = ['cv', 'identidad', 'otros']
    if folder not in allowed_folders:
        return jsonify({"error": "Acceso no autorizado a esta carpeta."}), 403

    # Construye la ruta al directorio de uploads de forma segura
    # getcwd() obtiene el directorio de trabajo actual (donde corre app.py)
    upload_dir = os.path.join(os.getcwd(), 'uploads', folder)
    
    try:
        # La función de Flask 'send_from_directory' se encarga de servir el archivo de forma segura.
        # as_attachment=False intenta mostrar el archivo en el navegador (ej. un PDF) en lugar de descargarlo.
        return send_from_directory(upload_dir, filename, as_attachment=False)
    except FileNotFoundError:
        return jsonify({"error": "Archivo no encontrado."}), 404


@app.route('/api/internal/chat_context/<string:identity_number>', methods=['GET'])
@require_api_key
def get_chat_context_by_identity(identity_number):
    """
    Endpoint interno para que bridge.js obtenga el contexto completo de un
    afiliado para mostrarlo en el panel de chat.
    Devuelve información básica y sus últimas 3 postulaciones.
    """
    clean_identity = str(identity_number).replace('-', '').strip()
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "DB connection failed"}), 500
    
    cursor = conn.cursor(dictionary=True)
    try:
        context_data = {
            "info_basica": None,
            "ultimas_postulaciones": []
        }

        # 1. Obtener información básica del afiliado
        cursor.execute("SELECT id_afiliado, nombre_completo, identidad, telefono, ciudad FROM Afiliados WHERE identidad = %s", (clean_identity,))
        info_basica = cursor.fetchone()

        if not info_basica:
            return jsonify({"error": "Afiliado no encontrado"}), 404
            
        context_data["info_basica"] = info_basica
        id_afiliado = info_basica['id_afiliado']

        # 2. Obtener las últimas 3 postulaciones del afiliado
        postulaciones_query = """
            SELECT p.id_postulacion, p.fecha_aplicacion, p.estado, v.cargo_solicitado, c.empresa
            FROM Postulaciones p
            JOIN Vacantes v ON p.id_vacante = v.id_vacante
            JOIN Clientes c ON v.id_cliente = c.id_cliente
            WHERE p.id_afiliado = %s
            ORDER BY p.fecha_aplicacion DESC
            LIMIT 3
        """
        cursor.execute(postulaciones_query, (id_afiliado,))
        postulaciones = cursor.fetchall()

        # Formatear fechas para que sean compatibles con JSON
        for p in postulaciones:
            if isinstance(p.get('fecha_aplicacion'), (datetime, date)):
                p['fecha_aplicacion'] = p['fecha_aplicacion'].isoformat()

        context_data["ultimas_postulaciones"] = postulaciones

        return jsonify(context_data)
        
    except Exception as e:
        app.logger.error(f"Error en el endpoint de contexto de chat: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()
        

# --- INICIO DE CÓDIGO A AÑADIR ---
def create_initial_user():
    """
    Verifica si existe un usuario inicial y, si no, lo crea.
    Ideal para la primera ejecución del sistema.
    """
    conn = get_db_connection()
    if not conn:
        app.logger.error("ERROR: No se pudo conectar a la BD para crear el usuario inicial.")
        return
    
    cursor = conn.cursor()
    
    try:
        # --- CONFIGURA TUS CREDENCIALES INICIALES AQUÍ ---
        initial_email = "agencia.henmir@gmail.com"
        initial_password = "Nc044700" # ¡CÁMBIALA!

        # Revisa si el usuario ya existe
        cursor.execute("SELECT id FROM Users WHERE email = %s", (initial_email,))
        if cursor.fetchone():
            app.logger.info(f"INFO: El usuario '{initial_email}' ya existe.")
            return

        # Si no existe, lo crea
        app.logger.info(f"INFO: Creando usuario inicial '{initial_email}'...")
        hashed_password = bcrypt.hashpw(initial_password.encode('utf-8'), bcrypt.gensalt())
        
        query = "INSERT INTO Users (email, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (initial_email, hashed_password.decode('utf-8')))
        conn.commit()
        app.logger.info(f"ÉXITO: Usuario '{initial_email}' creado. ¡Recuerda esta contraseña!")

    except Exception as e:
        app.logger.error(f"ERROR: No se pudo crear el usuario inicial. {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
    finally:
        cursor.close()
        conn.close()

# --- ACCIÓN: Llama a la función aquí ---
create_initial_user()

    
# --- PUNTO DE ENTRADA PARA EJECUTAR EL SERVIDOR (SIN CAMBIOS) ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



# =================================================================
# =================================================================
# == INICIO DEL NUEVO BLOQUE DE CÓDIGO PARA EL PORTAL PÚBLICO ==
# =================================================================
# =================================================================

# ===============================================================
# SECCIÓN 9: API PÚBLICA PARA EL SITIO WEB (GitHub Pages)
# ===============================================================

@app.route('/public-api/vacancies', methods=['GET'])
def public_get_vacancies():
    """Devuelve una lista de vacantes activas con información pública."""
    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "error": "Error de conexión con el servidor."}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        # Seleccionamos solo los campos seguros para mostrar públicamente
        query = """
            SELECT
                id_vacante,
                cargo_solicitado AS puesto,
                ciudad,
                requisitos,
                salario
            FROM Vacantes
            WHERE estado = 'Abierta'
            ORDER BY fecha_apertura DESC;
        """
        cursor.execute(query)
        vacancies = cursor.fetchall()
        # Convertir Decimal a float para que sea serializable a JSON
        for v in vacancies:
            if isinstance(v.get('salario'), Decimal):
                v['salario'] = float(v['salario'])
        return jsonify({"success": True, "data": vacancies})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/public-api/status/<string:identity_number>', methods=['GET'])
def public_get_candidate_status(identity_number):
    """
    Consulta el perfil completo de un candidato, incluyendo postulaciones,
    entrevistas y solicitudes de postulación.
    """
    clean_identity = str(identity_number).replace('-', '').strip()
    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "error": "Error de conexión."}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        # 1. Verificar si el afiliado existe
        cursor.execute("SELECT id_afiliado, nombre_completo FROM Afiliados WHERE identidad = %s", (clean_identity,))
        afiliado = cursor.fetchone()

        if not afiliado:
            return jsonify({"success": True, "data": {"status": "not_registered"}})

        id_afiliado = afiliado['id_afiliado']

        # 2. Obtener postulaciones y entrevistas asociadas (sin nombres de empresa)
        query_applications = """
            SELECT
                p.fecha_aplicacion,
                p.estado,
                v.cargo_solicitado,
                e.fecha_hora AS fecha_entrevista
            FROM Postulaciones p
            JOIN Vacantes v ON p.id_vacante = v.id_vacante
            LEFT JOIN Entrevistas e ON p.id_postulacion = e.id_postulacion AND e.resultado = 'Programada'
            WHERE p.id_afiliado = %s
            ORDER BY p.fecha_aplicacion DESC;
        """
        cursor.execute(query_applications, (id_afiliado,))
        applications = cursor.fetchall()

        # 3. Obtener el estado de las solicitudes de postulación
        query_requests = """
            SELECT
                sr.fecha_solicitud,
                sr.estado,
                v.cargo_solicitado
            FROM Solicitudes_Postulacion sr
            JOIN Vacantes v ON sr.id_vacante = v.id_vacante
            WHERE sr.id_afiliado = %s
            ORDER BY sr.fecha_solicitud DESC;
        """
        cursor.execute(query_requests, (id_afiliado,))
        application_requests = cursor.fetchall()

        # Formatear todas las fechas para que sean legibles
        for app in applications:
            if app.get('fecha_aplicacion'):
                app['fecha_aplicacion'] = app['fecha_aplicacion'].strftime('%d de %B de %Y')
            if app.get('fecha_entrevista'):
                app['fecha_entrevista'] = app['fecha_entrevista'].strftime('%A, %d de %B a las %I:%M %p')
        
        for req in application_requests:
            if req.get('fecha_solicitud'):
                req['fecha_solicitud'] = req['fecha_solicitud'].strftime('%d de %B de %Y')

        return jsonify({
            "success": True,
            "data": {
                "status": "profile_found",
                "candidate_name": afiliado['nombre_completo'],
                "applications": applications,
                "application_requests": application_requests
            }
        })
    except Exception as e:
        app.logger.error(f"Error en public_get_candidate_status: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/public-api/contact', methods=['POST'])
def public_contact_form():
    """Recibe y guarda los envíos del formulario de contacto."""
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    subject = data.get('subject')
    message = data.get('message')

    if not all([name, email, subject, message]):
        return jsonify({"success": False, "error": "Todos los campos son requeridos."}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"success": False, "error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        sql = "INSERT INTO Mensajes_Contacto (nombre, email, asunto, mensaje) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (name, email, subject, message))
        conn.commit()
        return jsonify({"success": True, "message": "Mensaje recibido. ¡Gracias por contactarnos!"})
    except Exception as e:
        conn.rollback()
        app.logger.error(f"ERROR en /public-api/contact: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"success": False, "error": "Ocurrió un error en el servidor."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/public-api/register', methods=['POST'])
def public_register_candidate():
    """
    Recibe datos Y ARCHIVOS del formulario de registro, sube los archivos a Google Drive
    y guarda la información (incluyendo las URLs de los archivos) en la BD.
    """
    try:
        data = request.form
        identidad = str(data.get('identidad', '')).replace('-', '').strip()

        # --- Validación de datos ---
        required_fields = ['nombre_completo', 'identidad', 'telefono', 'email', 'ciudad', 'grado_academico', 'experiencia']
        if not all(data.get(field) for field in required_fields):
            return jsonify({"success": False, "error": "Todos los campos de texto son obligatorios."}), 400

        # --- VALIDACIONES DE SEGURIDAD PARA ARCHIVOS ---
        # Tipos MIME permitidos para cada tipo de documento
        ALLOWED_CV_TYPES = {
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        ALLOWED_ID_TYPES = {
            'application/pdf',
            'image/jpeg',
            'image/jpg', 
            'image/png',
            'image/webp'
        }
        
        # Tamaño máximo: 5MB
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB en bytes
        
        def validate_file_security(file, allowed_types, file_type_name):
            """Valida tipo MIME y tamaño de archivo"""
            if not file or file.filename == '':
                return None, None
                
            # Validar tipo MIME
            if file.content_type not in allowed_types:
                return None, f"Tipo de archivo no permitido para {file_type_name}. Tipos permitidos: {', '.join(allowed_types)}"
            
            # Validar tamaño
            file.seek(0, 2)  # Ir al final del archivo
            file_size = file.tell()
            file.seek(0)  # Regresar al inicio
            
            if file_size > MAX_FILE_SIZE:
                return None, f"El archivo {file_type_name} excede el tamaño máximo de 5MB. Tamaño actual: {file_size / (1024*1024):.2f}MB"
            
            return file, None

        # --- Manejo de Archivos con validaciones de seguridad ---
        cv_url = None
        identidad_urls = []

        # Validar y subir CV
        if 'cv_file' in request.files:
            cv_file, error = validate_file_security(request.files['cv_file'], ALLOWED_CV_TYPES, "CV")
            if error:
                return jsonify({"success": False, "error": error}), 400
            if cv_file:
                # Crear un nombre de archivo único y seguro
                unique_filename = generate_secure_filename("CV", identidad, cv_file.filename)
                cv_url = upload_file_to_drive(cv_file, unique_filename)

        # Validar y subir archivos de identidad
        if 'identidad_files' in request.files:
            identidad_files = request.files.getlist('identidad_files')
            for i, file in enumerate(identidad_files):
                validated_file, error = validate_file_security(file, ALLOWED_ID_TYPES, "documento de identidad")
                if error:
                    return jsonify({"success": False, "error": error}), 400
                if validated_file:
                    unique_filename = generate_secure_filename("ID", identidad, validated_file.filename, i+1)
                    url = upload_file_to_drive(validated_file, unique_filename)
                    if url:
                        identidad_urls.append(url)
        contrato_url = ", ".join(identidad_urls) if identidad_urls else None

        # --- Preparación de datos para la BD ---
        email = data.get('email') or None
        rotativos = 1 if str(data.get('disponibilidad_rotativos')).strip().lower() == 'si' else 0
        transporte = 1 if str(data.get('transporte_propio')).strip().lower() == 'si' else 0
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"success": False, "error": "Error de conexión con la base de datos."}), 500
        cursor = conn.cursor()

        sql_upsert = """
            INSERT INTO Afiliados (fecha_registro, nombre_completo, identidad, telefono, email, experiencia, ciudad, grado_academico, cv_url, contrato_url, disponibilidad_rotativos, transporte_propio)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                nombre_completo=VALUES(nombre_completo), telefono=VALUES(telefono), email=VALUES(email),
                experiencia=VALUES(experiencia), ciudad=VALUES(ciudad), grado_academico=VALUES(grado_academico),
                cv_url=IF(VALUES(cv_url) IS NOT NULL, VALUES(cv_url), cv_url),
                contrato_url=IF(VALUES(contrato_url) IS NOT NULL, VALUES(contrato_url), contrato_url),
                disponibilidad_rotativos=VALUES(disponibilidad_rotativos), transporte_propio=VALUES(transporte_propio);
        """
        
        data_tuple = (
            get_honduras_time(), data.get('nombre_completo'), identidad, data.get('telefono'), 
            email, data.get('experiencia'), data.get('ciudad'), data.get('grado_academico'), 
            cv_url, contrato_url, rotativos, transporte
        )
        
        cursor.execute(sql_upsert, data_tuple)
        conn.commit()

        return jsonify({"success": True, "message": "Candidato registrado exitosamente."}), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": "Ocurrió un error interno al procesar tu registro."}), 500
    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()



# NOTA: Las rutas /public-api/register y /public-api/request-application se añadirían aquí
# siguiendo el mismo patrón si se implementa esa funcionalidad en el futuro.

# ===============================================================
# SECCIÓN 10: NUEVOS ENDPOINTS PARA EL CRM (Gestión de Solicitudes)
# ===============================================================

@app.route('/api/application-requests', methods=['GET'])
@token_required
def get_application_requests():
    """Devuelve al CRM las solicitudes de postulación pendientes."""
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT
                sr.id_solicitud,
                sr.fecha_solicitud,
                a.id_afiliado,
                a.nombre_completo,
                a.cv_url,
                v.id_vacante,
                v.cargo_solicitado
            FROM Solicitudes_Postulacion sr
            JOIN Afiliados a ON sr.id_afiliado = a.id_afiliado
            JOIN Vacantes v ON sr.id_vacante = v.id_vacante
            WHERE sr.estado = 'pendiente'
            ORDER BY sr.fecha_solicitud ASC;
        """
        cursor.execute(query)
        requests = cursor.fetchall()
        for req in requests:
            if isinstance(req.get('fecha_solicitud'), (datetime, date)):
                req['fecha_solicitud'] = req['fecha_solicitud'].isoformat()
        return jsonify(requests)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/process-request/<int:request_id>', methods=['POST'])
@token_required
def process_application_request(request_id):
    """Procesa una solicitud (aprobar o rechazar) desde el CRM."""
    data = request.get_json()
    action = data.get('action') # 'approve' o 'decline'
    comment = data.get('comment', '')

    if not action:
        return jsonify({"success": False, "error": "Acción no especificada."}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"success": False, "error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        # Obtener datos de la solicitud
        cursor.execute("SELECT id_afiliado, id_vacante FROM Solicitudes_Postulacion WHERE id_solicitud = %s", (request_id,))
        solicitud = cursor.fetchone()
        if not solicitud:
            return jsonify({"success": False, "error": "Solicitud no encontrada."}), 404

        if action == 'approve':
            # Insertar en la tabla principal de Postulaciones
            sql_insert = "INSERT INTO Postulaciones (id_afiliado, id_vacante, fecha_aplicacion, estado, comentarios) VALUES (%s, %s, NOW(), 'Recibida', 'Postulación aprobada desde el portal web.')"
            cursor.execute(sql_insert, (solicitud['id_afiliado'], solicitud['id_vacante']))
            # Actualizar el estado de la solicitud
            cursor.execute("UPDATE Solicitudes_Postulacion SET estado = 'aprobada' WHERE id_solicitud = %s", (request_id,))
            conn.commit()
            return jsonify({"success": True, "message": "Solicitud aprobada y postulación creada."})
        
        elif action == 'decline':
            # Actualizar el estado y guardar el comentario
            cursor.execute("UPDATE Solicitudes_Postulacion SET estado = 'rechazada', comentario_rechazo = %s WHERE id_solicitud = %s", (comment, request_id))
            conn.commit()
            return jsonify({"success": True, "message": "Solicitud rechazada."})
        
        else:
            return jsonify({"success": False, "error": "Acción no válida."}), 400

    except mysql.connector.Error as err:
        conn.rollback()
        # Error 1062 es para entradas duplicadas
        if err.errno == 1062:
            # Si ya existe, consideramos la aprobación como exitosa para quitarla de pendientes
            cursor.execute("UPDATE Solicitudes_Postulacion SET estado = 'aprobada', comentario_rechazo = 'Ya existía una postulación previa.' WHERE id_solicitud = %s", (request_id,))
            conn.commit()
            return jsonify({"success": True, "message": "El candidato ya había postulado. La solicitud se marcó como procesada."})
        return jsonify({"success": False, "error": str(err)}), 500
    except Exception as e:
        conn.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# =================================================================
# == FIN DEL NUEVO BLOQUE DE CÓDIGO ==
# =================================================================

@app.route('/public-api/test', methods=['GET'])
def public_test_connection():
    """Endpoint para probar la conexión desde la interfaz web."""
    return jsonify({
        "success": True,
        "message": "Conexión exitosa con el servidor Henmir",
        "timestamp": datetime.now().isoformat(),
        "server": "PythonAnywhere"
    })
    
    
# AÑADE ESTA NUEVA RUTA EN LA SECCIÓN 10 DE app.py

@app.route('/public-api/request-application-jsonp', methods=['GET'])
def public_request_application_jsonp():
    """
    Recibe una solicitud de postulación vía JSONP para evitar problemas de CORS.
    Los datos vienen como parámetros en la URL.
    """
    callback_function = request.args.get('callback', 'callback')
    identity_number = request.args.get('identity_number')
    vacancy_id = request.args.get('vacancy_id')

    if not identity_number or not vacancy_id:
        error_payload = json.dumps({"success": False, "error": "Faltan datos requeridos."})
        return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')

    conn = get_db_connection()
    if not conn:
        error_payload = json.dumps({"success": False, "error": "Error de BD"})
        return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')
    
    cursor = conn.cursor(dictionary=True)
    try:
        # 1. Encontrar al afiliado
        cursor.execute("SELECT id_afiliado FROM Afiliados WHERE identidad = %s", (str(identity_number).replace('-', '').strip(),))
        afiliado = cursor.fetchone()
        if not afiliado:
            error_payload = json.dumps({"success": False, "error": "No se encontró un candidato con esa identidad."})
            return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')
        
        id_afiliado = afiliado['id_afiliado']

        # 2. Verificar duplicados
        cursor.execute("SELECT id_solicitud FROM Solicitudes_Postulacion WHERE id_afiliado = %s AND id_vacante = %s", (id_afiliado, vacancy_id))
        if cursor.fetchone():
            payload = json.dumps({"success": True, "message": "Ya has enviado una solicitud para esta vacante."})
            return Response(f"{callback_function}({payload})", mimetype='application/javascript')
        
        cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_afiliado = %s AND id_vacante = %s", (id_afiliado, vacancy_id))
        if cursor.fetchone():
            payload = json.dumps({"success": True, "message": "Ya estás postulando a esta vacante."})
            return Response(f"{callback_function}({payload})", mimetype='application/javascript')

        # 3. Insertar la solicitud
        sql = "INSERT INTO Solicitudes_Postulacion (id_afiliado, id_vacante) VALUES (%s, %s)"
        cursor.execute(sql, (id_afiliado, vacancy_id))
        conn.commit()
        
        success_payload = json.dumps({"success": True, "message": "Tu solicitud ha sido enviada al equipo de reclutamiento. ¡Gracias!"})
        return Response(f"{callback_function}({success_payload})", mimetype='application/javascript')

    except Exception as e:
        conn.rollback()
        app.logger.error(f"ERROR en /public-api/request-application-jsonp: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        error_payload = json.dumps({"success": False, "error": "Ocurrió un error en el servidor."})
        return Response(f"{callback_function}({error_payload})", mimetype='application/javascript')
    finally:
        cursor.close()
        conn.close()
        
# ===============================================================
# SECCIÓN 11: GESTIÓN DE NOTICIAS (BLOG)
# ===============================================================

# --- ENDPOINT PÚBLICO PARA EL SITIO WEB ---
@app.route('/public-api/posts', methods=['GET'])
def public_get_posts():
    """Devuelve una lista de todos los posts publicados."""
    conn = get_db_connection()
    if not conn: return jsonify({"success": False, "error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        query = "SELECT * FROM Posts WHERE estado = 'publicado' ORDER BY fecha_publicacion DESC"
        cursor.execute(query)
        posts = cursor.fetchall()
        for post in posts:
            if isinstance(post.get('fecha_publicacion'), (datetime, date)):
                post['fecha_publicacion'] = post['fecha_publicacion'].isoformat()
        return jsonify({"success": True, "data": posts})
    finally:
        cursor.close()
        conn.close()

# --- ENDPOINTS PRIVADOS PARA EL PANEL DE CRM ---
@app.route('/api/posts', methods=['GET', 'POST'])
@token_required
def handle_posts():
    """Obtiene todos los posts (incluyendo borradores) o crea uno nuevo."""
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Posts ORDER BY fecha_publicacion DESC")
            posts = cursor.fetchall()
            for post in posts:
                if isinstance(post.get('fecha_publicacion'), (datetime, date)):
                    post['fecha_publicacion'] = post['fecha_publicacion'].isoformat()
            return jsonify(posts)

        elif request.method == 'POST':
            data = request.get_json()
            sql = """
                INSERT INTO Posts (title, excerpt, content, image_url, author, estado)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                data['title'], data['excerpt'], data['content'],
                data['image_url'], data['author'], data.get('estado', 'publicado')
            ))
            conn.commit()
            return jsonify({"success": True, "message": "Post creado exitosamente."}), 201
    finally:
        cursor.close()
        conn.close()

@app.route('/api/posts/<int:post_id>', methods=['PUT', 'DELETE'])
@token_required
def handle_single_post(post_id):
    """Actualiza o elimina un post específico."""
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor()
    try:
        if request.method == 'PUT':
            data = request.get_json()
            sql = """
                UPDATE Posts SET title=%s, excerpt=%s, content=%s, image_url=%s, author=%s, estado=%s
                WHERE id_post=%s
            """
            cursor.execute(sql, (
                data['title'], data['excerpt'], data['content'],
                data['image_url'], data['author'], data.get('estado', 'publicado'),
                post_id
            ))
            conn.commit()
            return jsonify({"success": True, "message": "Post actualizado."})

        elif request.method == 'DELETE':
            cursor.execute("DELETE FROM Posts WHERE id_post = %s", (post_id,))
            conn.commit()
            return jsonify({"success": True, "message": "Post eliminado."})
    finally:
        cursor.close()
        conn.close()
        
        
@app.route('/api/contact-messages', methods=['GET'])
@token_required
def get_contact_messages():
    """Devuelve todos los mensajes de contacto al CRM."""
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM Mensajes_Contacto ORDER BY fecha_recepcion DESC")
        messages = cursor.fetchall()
        for msg in messages:
            if isinstance(msg.get('fecha_recepcion'), (datetime, date)):
                msg['fecha_recepcion'] = msg['fecha_recepcion'].isoformat()
        return jsonify(messages)
    finally:
        cursor.close()
        conn.close()