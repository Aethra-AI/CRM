# Almacenamiento Local para CRM Henmir
import os
from werkzeug.utils import secure_filename
from datetime import datetime
import stat
import re
import hashlib

def generate_secure_filename_enhanced(doc_type, user_id, original_filename, sequence=None):
    """
    Genera un nombre de archivo completamente seguro y único con validaciones adicionales.
    
    Args:
        doc_type: Tipo de documento ("CV", "ID", etc.)
        user_id: Identificador del usuario (cédula limpia)
        original_filename: Nombre original del archivo
        sequence: Número de secuencia para múltiples archivos (opcional)
    
    Returns:
        str: Nombre de archivo seguro y único
    """
    # Sanitizar completamente el nombre original
    safe_original = re.sub(r'[^a-zA-Z0-9._-]', '_', str(original_filename))
    safe_original = re.sub(r'_{2,}', '_', safe_original)  # Reducir múltiples underscores
    safe_original = safe_original.strip('._-')  # Remover caracteres al inicio/final
    
    # Obtener extensión de forma segura
    if '.' in safe_original:
        name_part, extension = safe_original.rsplit('.', 1)
        # Lista blanca de extensiones permitidas
        allowed_extensions = ['pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'webp']
        extension = extension.lower()[:10]
        if extension not in allowed_extensions:
            extension = 'bin'  # Extensión segura por defecto
    else:
        name_part = safe_original[:50]  # Limitar longitud
        extension = 'bin'
    
    # Sanitizar user_id
    clean_user_id = re.sub(r'[^a-zA-Z0-9]', '', str(user_id))[:20]
    
    # Crear timestamp único con microsegundos
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    
    # Crear hash único para prevenir colisiones
    hash_input = f"{doc_type}_{clean_user_id}_{timestamp}_{name_part}"
    file_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:12]  # SHA256 más seguro
    
    # Construir nombre final con componentes seguros
    components = [doc_type[:10], clean_user_id, timestamp, file_hash]
    if sequence:
        components.append(f"seq{int(sequence):03d}")  # Formato consistente
    
    final_name = "_".join(components) + f".{extension}"
    
    # Asegurar límites del sistema de archivos (255 caracteres max)
    if len(final_name) > 255:
        # Truncar manteniendo la extensión
        max_base_length = 255 - len(extension) - 1
        base_name = "_".join(components)
        if len(base_name) > max_base_length:
            base_name = base_name[:max_base_length]
        final_name = f"{base_name}.{extension}"
    
    return final_name

def upload_file_to_drive(file_storage, filename):
    """
    Guarda archivos localmente en la VM y retorna una URL HTTP completa
    para que sea accesible desde cualquier lugar (como tu CRM local).
    
    Args:
        file_storage: Objeto de archivo de Flask (request.files['...'])
        filename: Nombre del archivo (ej: CV_12345678_documento.pdf)
    
    Returns:
        str: URL HTTP completa para acceder al archivo o None si hay un error.
    """
    try:
        # --- CONFIGURACIÓN DE LA URL PÚBLICA ---
        # IP pública de la VM y el puerto donde Gunicorn está sirviendo app.py
        vm_ip = "34.68.183.117"
        vm_port = 5000  # <-- ESTE ES EL PUERTO CORRECTO

        # Determinar la carpeta de destino según el tipo de archivo
        if filename.startswith('CV_'):
            upload_folder = 'uploads/cv'
            file_type = 'CV'
        elif filename.startswith('ID_'):
            upload_folder = 'uploads/identidad'
            file_type = 'Identidad'
        else:
            upload_folder = 'uploads/otros'
            file_type = 'Documento'
            
        # Crear la carpeta si no existe
        os.makedirs(upload_folder, exist_ok=True)
        
        # Usar la función de generación segura de nombres
        # Extraer información del nombre de archivo para usar la función mejorada
        if filename.startswith('CV_'):
            parts = filename.split('_', 2)
            if len(parts) >= 3:
                doc_type, user_id = parts[0], parts[1]
                original_name = parts[2]
            else:
                doc_type, user_id, original_name = 'CV', 'unknown', filename
        elif filename.startswith('ID_'):
            parts = filename.split('_', 3)
            if len(parts) >= 4:
                doc_type, user_id, seq = parts[0], parts[1], parts[2]
                original_name = parts[3]
                sequence = int(seq) if seq.isdigit() else None
            else:
                doc_type, user_id, original_name, sequence = 'ID', 'unknown', filename, None
        else:
            doc_type, user_id, original_name, sequence = 'DOC', 'unknown', filename, None
        
        # Generar nombre seguro
        final_filename = generate_secure_filename_enhanced(
            doc_type, user_id, original_name, 
            sequence if 'sequence' in locals() else None
        )
        
        # Construir la ruta completa donde se guardará el archivo en el servidor
        file_path = os.path.join(upload_folder, final_filename)
        
        # Guardar el archivo en el disco
        file_storage.seek(0)  # Buena práctica: resetear el puntero del archivo
        file_storage.save(file_path)
        
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
                
        # --- LÍNEA CORREGIDA ---
        # Generar la URL HTTP pública y completa con la IP y el PUERTO CORRECTO (5000)
        public_url = f"http://{vm_ip}:{vm_port}/uploads/{os.path.basename(upload_folder)}/{final_filename}"
        
        # Log para depuración en la terminal del servidor con información de seguridad
        file_size = os.path.getsize(file_path)
        print(f"✅ {file_type} guardado de forma segura: {final_filename} ({file_size} bytes)")
        print(f"📂 Ruta local: {file_path}")
        print(f"🔗 URL HTTP generada: {public_url}")
        print(f"🔒 Nombre sanitizado y hash aplicado para seguridad")
        
        return public_url
        
    except Exception as e:
        print(f"❌ Error guardando archivo '{filename}': {e}")
        # Log adicional para debugging de seguridad
        print(f"🚨 Error de seguridad potencial detectado en subida de archivo")
        return None

def get_file_info(file_path):
    """
    Obtiene información de un archivo guardado localmente.
    
    Args:
        file_path: Ruta del archivo
        
    Returns:
        dict: Información del archivo (tamaño, fecha, etc.)
    """
    try:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            return {
                'exists': True,
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime),
                'modified': datetime.fromtimestamp(stat.st_mtime)
            }
        else:
            return {'exists': False}
    except Exception as e:
        print(f"Error obteniendo info de archivo: {e}")
        return {'exists': False, 'error': str(e)}