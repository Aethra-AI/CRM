# Celery Tasks para CRM Henmir
# Configuración de tareas asíncronas para notificaciones WhatsApp

import os
from celery import Celery
import requests
import mysql.connector
from datetime import datetime
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración de Celery
celery_app = Celery('henmir_crm')

# Configuración del broker (Redis recomendado para producción)
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery_app.conf.broker_url = REDIS_URL
celery_app.conf.result_backend = REDIS_URL

# Configuraciones adicionales de Celery
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='America/Tegucigalpa',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutos máximo por tarea
    task_soft_time_limit=25 * 60,  # 25 minutos soft limit
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_disable_rate_limits=False,
    task_compression='gzip',
    result_compression='gzip',
)

def get_db_connection():
    """Obtiene conexión a la base de datos"""
    try:
        return mysql.connector.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            user=os.getenv('DB_USER', 'root'),
            password=os.getenv('DB_PASSWORD', ''),
            database=os.getenv('DB_NAME', 'henmir_crm'),
            charset='utf8mb4',
            collation='utf8mb4_unicode_ci'
        )
    except Exception as e:
        logger.error(f"Error conectando a la BD: {e}")
        return None

def clean_phone_number(phone_str):
    """Limpia y estandariza los números de teléfono para Honduras."""
    import re
    if not phone_str:
        return None
    digits = re.sub(r'\D', '', str(phone_str))
    if digits.startswith('504') and len(digits) == 11:
        return digits
    if len(digits) == 8:
        return f"504{digits}"
    return digits if len(digits) >= 8 else None

@celery_app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def send_whatsapp_notification_task(self, task_type, related_id, phone_number, message_body, candidate_name=None):
    """
    Tarea asíncrona para enviar notificaciones de WhatsApp.
    
    Args:
        task_type: Tipo de tarea ('postulation', 'interview', 'hired')
        related_id: ID relacionado (postulation_id, interview_id, etc.)
        phone_number: Número de teléfono del destinatario
        message_body: Cuerpo del mensaje a enviar
        candidate_name: Nombre del candidato (opcional)
    
    Returns:
        dict: Resultado de la operación
    """
    try:
        logger.info(f"Iniciando tarea WhatsApp: {task_type} para {candidate_name or 'candidato'}")
        
        # Limpiar número de teléfono
        clean_phone = clean_phone_number(phone_number)
        if not clean_phone:
            raise ValueError(f"Número de teléfono inválido: {phone_number}")
        
        # Preparar datos para bridge.js
        bridge_url = os.getenv('BRIDGE_URL', 'http://localhost:3000')
        task_data = {
            "task_type": task_type,
            "related_id": related_id,
            "chat_id": clean_phone,
            "message_body": message_body,
            "timestamp": datetime.now().isoformat()
        }
        
        # Enviar a bridge.js
        response = requests.post(
            f"{bridge_url}/api/send-task",
            json=task_data,
            timeout=30,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            logger.info(f"Notificación WhatsApp enviada exitosamente: {task_type}")
            
            # Actualizar estado en la base de datos
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    if task_type == 'postulation':
                        cursor.execute(
                            "UPDATE Postulaciones SET whatsapp_notification_status = 'sent' WHERE id_postulacion = %s",
                            (related_id,)
                        )
                    elif task_type == 'interview':
                        cursor.execute(
                            "UPDATE Entrevistas SET notification_status = 'sent' WHERE id_entrevista = %s",
                            (related_id,)
                        )
                    elif task_type == 'hired':
                        cursor.execute(
                            "UPDATE Contratados SET notification_status = 'sent' WHERE id_contratado = %s",
                            (related_id,)
                        )
                    
                    conn.commit()
                    logger.info(f"Estado de notificación actualizado en BD para {task_type}")
                    
                except Exception as db_error:
                    logger.error(f"Error actualizando BD: {db_error}")
                    conn.rollback()
                finally:
                    cursor.close()
                    conn.close()
            
            return {
                'success': True,
                'task_type': task_type,
                'related_id': related_id,
                'phone_number': clean_phone,
                'message': 'Notificación enviada exitosamente'
            }
        else:
            error_msg = f"Error en bridge.js: {response.status_code} - {response.text}"
            logger.error(error_msg)
            raise Exception(error_msg)
            
    except Exception as exc:
        logger.error(f"Error en tarea WhatsApp {task_type}: {exc}")
        
        # Actualizar estado de error en BD
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                if task_type == 'postulation':
                    cursor.execute(
                        "UPDATE Postulaciones SET whatsapp_notification_status = 'failed' WHERE id_postulacion = %s",
                        (related_id,)
                    )
                elif task_type == 'interview':
                    cursor.execute(
                        "UPDATE Entrevistas SET notification_status = 'failed' WHERE id_entrevista = %s",
                        (related_id,)
                    )
                elif task_type == 'hired':
                    cursor.execute(
                        "UPDATE Contratados SET notification_status = 'failed' WHERE id_contratado = %s",
                        (related_id,)
                    )
                
                conn.commit()
            except Exception as db_error:
                logger.error(f"Error actualizando estado de fallo en BD: {db_error}")
            finally:
                cursor.close()
                conn.close()
        
        # Re-lanzar excepción para retry automático
        raise self.retry(exc=exc)

@celery_app.task(bind=True)
def get_task_status(self, task_id):
    """
    Obtiene el estado de una tarea de Celery.
    
    Args:
        task_id: ID de la tarea a consultar
    
    Returns:
        dict: Estado de la tarea
    """
    try:
        result = celery_app.AsyncResult(task_id)
        return {
            'task_id': task_id,
            'status': result.status,
            'result': result.result if result.ready() else None,
            'traceback': result.traceback if result.failed() else None
        }
    except Exception as e:
        logger.error(f"Error obteniendo estado de tarea {task_id}: {e}")
        return {
            'task_id': task_id,
            'status': 'ERROR',
            'error': str(e)
        }

# Configuración para auto-discovery de tareas
if __name__ == '__main__':
    celery_app.start()
