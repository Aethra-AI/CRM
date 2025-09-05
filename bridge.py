# ==================================================================
# =================== SERVIDOR BRIDGE DE HENMIR ====================
# ==================================================================
# Este servidor Flask actúa como un intermediario seguro y rápido
# entre el frontend público y el backend del CRM.

import os
import requests
from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_cors import CORS
from flask_caching import Cache
from dotenv import load_dotenv

# --- 1. CONFIGURACIÓN INICIAL ---
# ---------------------------------

# Carga las variables de entorno desde el archivo .env
load_dotenv()

# Inicializa la aplicación Flask
app = Flask(__name__,
            static_folder='static',  # Carpeta para archivos CSS, JS, imágenes
            template_folder='templates') # Carpeta para el index.html

# Configuración de CORS para permitir peticiones desde cualquier origen.
# En producción, podrías restringirlo a tu dominio específico.
CORS(app)

# Configuración de la caché del servidor.
# Usamos un caché simple en memoria, que es ideal para este caso de uso.
# Los datos cacheados se pierden si el servidor se reinicia.
config = {
    "DEBUG": True,
    "CACHE_TYPE": "SimpleCache",
    "CACHE_DEFAULT_TIMEOUT": 1800  # 30 minutos (30 * 60 segundos)
}
app.config.from_mapping(config)
cache = Cache(app)

# Lee las credenciales para comunicarse con el CRM desde las variables de entorno.
# Esto es crucial para la seguridad, nunca se deben escribir directamente en el código.
CRM_API_URL = os.getenv('CRM_API_URL')
CRM_API_KEY = os.getenv('CRM_API_KEY')

# Validación inicial: si no se configuran las variables del CRM, el servidor no arrancará.
if not CRM_API_URL or not CRM_API_KEY:
    raise ValueError("Error crítico: Las variables de entorno CRM_API_URL y CRM_API_KEY deben estar configuradas.")


# --- 2. FUNCIÓN AUXILIAR PARA LA COMUNICACIÓN CON EL CRM ---
# -----------------------------------------------------------

def query_crm(endpoint, method='GET', json_data=None, files_data=None):
    """
    Función centralizada para realizar llamadas seguras al API del CRM.
    Ahora soporta tanto JSON como FormData con archivos.
    
    Args:
        endpoint (str): El endpoint del CRM al que se quiere llamar (ej. '/public/vacancies').
        method (str): El método HTTP a utilizar ('GET', 'POST', etc.).
        json_data (dict, optional): El payload JSON para peticiones simples.
        files_data (dict, optional): FormData con archivos para peticiones multipart.

    Returns:
        tuple: Una tupla conteniendo (datos_json, status_code).
               En caso de error, datos_json contendrá un mensaje de error.
    """
    try:
        url = f"{CRM_API_URL}{endpoint}"
        headers = {'X-API-Key': CRM_API_KEY}
        
        #  Si hay archivos, enviamos FormData; si no, JSON
        if files_data:
            # Para FormData con archivos, NO ponemos Content-Type
            response = requests.post(url, headers=headers, data=files_data, timeout=30)
        elif method.upper() == 'POST':
            headers['Content-Type'] = 'application/json'
            response = requests.post(url, headers=headers, json=json_data, timeout=15)
        else: # GET por defecto
            response = requests.get(url, headers=headers, timeout=15)

        # Lanza una excepción si el CRM devuelve un error (4xx o 5xx)
        response.raise_for_status()
        
        return response.json(), response.status_code

    except requests.exceptions.HTTPError as http_err:
        # Errores devueltos por el API del CRM (ej. 401 Unauthorized, 404 Not Found)
        print(f"Error HTTP del CRM: {http_err.response.status_code} - {http_err.response.text}")
        return {"error": f"Error de comunicación con el servicio principal ({http_err.response.status_code})."}, http_err.response.status_code
    except requests.exceptions.RequestException as req_err:
        # Errores de red o conexión (ej. el CRM está caído)
        print(f"Error de conexión al CRM: {req_err}")
        return {"error": "No se pudo conectar con el servicio principal. Intente más tarde."}, 503
    except Exception as e:
        # Cualquier otro error inesperado
        print(f"Error inesperado al consultar el CRM: {e}")
        return {"error": "Ocurrió un error inesperado en el servidor."}, 500


# --- 3. ENDPOINTS PÚBLICOS (API PARA EL FRONTEND) ---
# ----------------------------------------------------
# Estas son las rutas que el archivo `app.js` consultará.

@app.route('/api/public/vacancies', methods=['GET'])
@cache.cached(timeout=300) # Caché de 5 minutos (5 * 60) para esta ruta
def get_public_vacancies():
    """
    Endpoint para obtener la lista de vacantes públicas.
    Llama al CRM, transforma los datos para seguridad y los devuelve.
    La respuesta se guarda en caché para mejorar el rendimiento.
    """
    print("CACHE MISS: Consultando vacantes al CRM...")
    crm_data, status_code = query_crm('/public/vacancies')
    
    if status_code != 200:
        return jsonify(crm_data), status_code
    
    # Transformación de datos: Aseguramos que solo se envíen los campos públicos.
    # Esto es una capa extra de seguridad.
    public_vacancies = [
        {
            "puesto": vac.get("puesto", "No especificado"),
            "ciudad": vac.get("ciudad", "No especificada"),
            "requisitos": vac.get("requisitos", "No especificados"),
            "salario": vac.get("salario") # Asumimos que el CRM ya lo formatea si es público
        } for vac in crm_data
    ]
    
    return jsonify(public_vacancies)


@app.route('/api/public/posts', methods=['GET'])
@cache.cached(timeout=900) # Caché de 15 minutos (15 * 60) para los posts
def get_public_posts():
    """
    Endpoint para obtener las noticias/posts del blog.
    (Actualmente es un placeholder, se conectará al CRM si se añade esa funcionalidad).
    """
    print("CACHE MISS: Consultando posts al CRM...")
    # --- NOTA: Este es un ejemplo. Necesitarás crear el endpoint en el CRM.
    # crm_data, status_code = query_crm('/public/posts')
    # if status_code != 200:
    #     return jsonify(crm_data), status_code
    # return jsonify(crm_data)
    
    # --- Datos de ejemplo mientras se crea el endpoint en el CRM ---
    mock_posts = [
        {"titulo": "Domina tu próxima entrevista", "contenido": "Descubre las claves para impresionar a los reclutadores y conseguir el puesto que deseas.", "imagen_url": "https://images.unsplash.com/photo-1573496130407-57329f01f769?q=80&w=2069&auto=format&fit=crop"},
        {"titulo": "Cómo crear un plan de desarrollo profesional", "contenido": "Define tus metas y traza la ruta hacia el éxito con una estrategia clara y efectiva.", "imagen_url": "https://images.unsplash.com/photo-1552664730-d307ca884978?q=80&w=2070&auto=format&fit=crop"},
        {"titulo": "Los 5 errores que debes evitar en tu CV", "contenido": "Asegúrate de que tu currículum destaque por las razones correctas evitando estos fallos comunes.", "imagen_url": "https://images.unsplash.com/photo-1450101499163-c8848c66ca85?q=80&w=2070&auto=format&fit=crop"},
    ]
    return jsonify(mock_posts)


@app.route('/api/public/register', methods=['POST'])
def register_candidate():
    """
    Endpoint para recibir los datos de registro con archivos.
    Maneja FormData correctamente y la reenvía al CRM.
    """
    try:
        # Obtener datos del formulario o JSON
        data = request.form.to_dict() if request.form else request.get_json() or {}
        
        # Validación básica en el Bridge
        required_fields = ['nombre_completo', 'identidad', 'telefono', 'email', 'ciudad']
        if not all(field in data and data[field] for field in required_fields):
            return jsonify({"error": "Faltan campos requeridos en el formulario."}), 400

        # Preparar datos para enviar al CRM
        if request.files:
            # Hay archivos - usar requests.post con files y data separados
            files_to_send = {}
            
            # Manejar CV
            if 'cv_file' in request.files:
                cv_file = request.files['cv_file']
                if cv_file.filename:
                    cv_file.seek(0)  # Resetear puntero
                    files_to_send['cv_file'] = (cv_file.filename, cv_file.read(), cv_file.content_type)
            
            # Manejar archivos de identidad
            if 'identidad_files' in request.files:
                identidad_files = request.files.getlist('identidad_files')
                for i, file in enumerate(identidad_files):
                    if file.filename:
                        file.seek(0)  # Resetear puntero
                        files_to_send[f'identidad_files'] = (file.filename, file.read(), file.content_type)

            # Enviar al CRM con archivos separados
            if files_to_send:
                crm_response, status_code = query_crm_with_files('/public-api/register', data, files_to_send)
            else:
                crm_response, status_code = query_crm('/public-api/register', method='POST', json_data=data)
        else:
            # Sin archivos - usar JSON
            crm_response, status_code = query_crm('/public-api/register', method='POST', json_data=data)
        
        return jsonify(crm_response), status_code
        
    except Exception as e:
        print(f"Error en Bridge register: {e}")
        return jsonify({"error": "Error interno del servidor."}), 500


def query_crm_with_files(endpoint, form_data, files_data):
    """
    Función específica para enviar archivos al CRM.
    Separa correctamente form data de archivos.
    """
    try:
        url = f"{CRM_API_URL}{endpoint}"
        headers = {'X-API-Key': CRM_API_KEY}
        
        # Enviar con requests.post separando data y files
        response = requests.post(
            url, 
            headers=headers, 
            data=form_data,  # Datos del formulario
            files=files_data,  # Archivos separados
            timeout=30
        )
        
        response.raise_for_status()
        return response.json(), response.status_code
        
    except requests.exceptions.HTTPError as http_err:
        print(f"Error HTTP del CRM: {http_err.response.status_code} - {http_err.response.text}")
        return {"error": f"Error de comunicación con el servicio principal ({http_err.response.status_code})."}, http_err.response.status_code
    except requests.exceptions.RequestException as req_err:
        print(f"Error de conexión al CRM: {req_err}")
        return {"error": "No se pudo conectar con el servicio principal. Intente más tarde."}, 503
    except Exception as e:
        print(f"Error inesperado al consultar el CRM: {e}")
        return {"error": "Ocurrió un error inesperado en el servidor."}, 500


@app.route('/api/public/status/<string:identity_number>', methods=['GET'])
def get_candidate_status(identity_number):
    """
    Endpoint para que un candidato consulte el estado de sus postulaciones.
    La identidad se pasa en la URL. Llama al endpoint correspondiente en el CRM.
    Este endpoint se cachea por un tiempo corto para evitar consultas repetidas del mismo usuario.
    """
    clean_identity = identity_number.strip().replace('-', '')
    
    # Usamos una clave de caché dinámica basada en la identidad
    cache_key = f"status_{clean_identity}"
    
    cached_response = cache.get(cache_key)
    if cached_response:
        print(f"CACHE HIT: Devolviendo estado para identidad {clean_identity} desde caché.")
        return jsonify(cached_response)

    print(f"CACHE MISS: Consultando estado para identidad {clean_identity} al CRM.")
    crm_response, status_code = query_crm(f'/public/candidate-status/{clean_identity}')
    
    if status_code == 200:
        # Guardamos la respuesta exitosa en caché por 15 minutos
        cache.set(cache_key, crm_response, timeout=900)
        
    return jsonify(crm_response), status_code


# --- 4. SERVIDOR DE ARCHIVOS ESTÁTICOS Y RUTA PRINCIPAL ---
# ---------------------------------------------------------
# Estas rutas se encargan de servir el frontend (HTML, CSS, JS).

@app.route('/uploads/<path:folder>/<path:filename>')
def serve_uploaded_files(folder, filename):
    """
    Sirve archivos subidos localmente (CVs, documentos de identidad).
    Solo permite acceso a las carpetas autorizadas.
    """
    # Seguridad: Solo permitir carpetas específicas
    allowed_folders = ['cv', 'identidad', 'otros']
    if folder not in allowed_folders:
        return jsonify({"error": "Carpeta no autorizada"}), 403
    
    try:
        upload_dir = os.path.join('uploads', folder)
        return send_from_directory(upload_dir, filename)
    except FileNotFoundError:
        return jsonify({"error": "Archivo no encontrado"}), 404

@app.route('/')
def api_status():
    """
    Endpoint de estado del Bridge API.
    Confirma que el servidor está operativo.
    """
    return jsonify({
        "status": "online",
        "service": "Henmir Bridge API",
        "version": "1.0",
        "endpoints": [
            "/api/public/register",
            "/api/public/vacancies", 
            "/api/public/status/<identity>",
            "/api/public/posts",
            "/uploads/<folder>/<filename>"
        ]
    })

# Flask maneja automáticamente los archivos en la carpeta 'static'.
# No necesitamos una ruta explícita para 'styles.css' o 'app.js' si están en /static.
# Por consistencia, nos aseguraremos de que las carpetas sean `templates` para HTML
# y `static` para CSS/JS.

# --- 5. PUNTO DE ENTRADA DE LA APLICACIÓN ---
# ---------------------------------------------

if __name__ == '__main__':
    # Ejecuta la aplicación en modo de desarrollo.
    # En PythonAnywhere, esto no se usará; el servidor WSGI lo manejará.
    app.run(host='0.0.0.0', port=5001, debug=True)