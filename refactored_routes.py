# =====================================================
# RUTAS REFACTORIZADAS CON AISLAMIENTO MULTI-TENANT
# =====================================================
# Este archivo contiene todas las funciones refactorizadas para incluir
# filtrado por tenant_id (id_cliente) en todas las operaciones de base de datos

# --- FUNCIONES AUXILIARES PARA ASISTENTE IA ---

def _get_candidate_id(conn, candidate_id: int = None, identity_number: str = None) -> int:
    """Función interna para obtener el id_afiliado. Prioriza el candidate_id si está presente."""
    if candidate_id:
        return candidate_id
    
    if identity_number:
        cursor = conn.cursor(dictionary=True)
        clean_identity = str(identity_number).replace('-', '').strip()
        # AÑADIDO: Filtro por tenant
        tenant_id = get_current_tenant_id()
        query = "SELECT id_afiliado FROM Afiliados WHERE identidad = %s AND id_cliente = %s LIMIT 1"
        cursor.execute(query, (clean_identity, tenant_id))
        result = cursor.fetchone()
        cursor.close()
        if result:
            return result['id_afiliado']
            
    return None

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

def prepare_whatsapp_campaign_tool(message_body: str, candidate_id: int = None, identity_number: str = None, candidate_ids: str = None, vacancy_id: int = None, application_date: str = None):
    """Prepara una campaña de WhatsApp con filtrado por tenant."""
    conn = get_db_connection()
    if not conn: return json.dumps({"error": "DB connection failed"})
    cursor = conn.cursor(dictionary=True)
    
    try:
        tenant_id = get_current_tenant_id()
        final_message_body = message_body
        if not final_message_body:
            cursor.execute("SELECT cuerpo_mensaje FROM Whatsapp_Templates WHERE id_template = 1 AND id_cliente = %s", (tenant_id,))
            template = cursor.fetchone()
            final_message_body = template['cuerpo_mensaje'] if template else "Hola [name], te contactamos de Henmir."

        candidates = []
        if candidate_id or identity_number:
            target_id = _get_candidate_id(conn, candidate_id, identity_number)
            if target_id:
                cursor.execute("SELECT id_afiliado, nombre_completo, telefono FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (target_id, tenant_id))
                candidates = cursor.fetchall()
        elif candidate_ids:
            id_list = re.findall(r'\b\d+\b', candidate_ids)
            if id_list:
                placeholders = ','.join(['%s'] * len(id_list))
                sql = f"SELECT id_afiliado, nombre_completo, telefono FROM Afiliados WHERE (id_afiliado IN ({placeholders}) OR identidad IN ({placeholders})) AND id_cliente = %s"
                cursor.execute(sql, id_list * 2 + [tenant_id])
                candidates = cursor.fetchall()

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

# --- RUTAS PRINCIPALES REFACTORIZADAS ---

@app.route('/api/candidates/search', methods=['GET'])
@token_required
def search_candidates():
    """Búsqueda de candidatos con filtrado por tenant."""
    try:
        term = request.args.get('q', '').strip()
        tags = request.args.get('tags', '') 
        registered_today = request.args.get('registered_today', 'false').lower() == 'true'
        
        results = _internal_search_candidates(term=term, tags=tags, registered_today=registered_today)
        
        if "error" in results:
            return jsonify(results), 500
            
        return jsonify(results)
        
    except Exception as e: 
        return jsonify({"error": str(e)}), 500

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
                SELECT E.*, P.id_vacante, V.cargo_solicitado 
                FROM Entrevistas E 
                JOIN Postulaciones P ON E.id_postulacion = P.id_postulacion 
                JOIN Vacantes V ON P.id_vacante = V.id_vacante 
                WHERE P.id_afiliado = %s AND E.id_cliente = %s
            """, (id_afiliado, tenant_id))
            perfil['entrevistas'] = cursor.fetchall()
            
            cursor.execute("""
                SELECT t.nombre_tag 
                FROM Tags t 
                JOIN Afiliado_Tags at ON t.id_tag = at.id_tag 
                WHERE at.id_afiliado = %s AND t.id_cliente = %s
            """, (id_afiliado, tenant_id))
            perfil['tags'] = [tag['nombre_tag'] for tag in cursor.fetchall()]
            
            return jsonify(perfil)
            
        elif request.method == 'PUT':
            data = request.get_json()
            update_fields = []
            params = []
            
            for field in ['nombre_completo', 'telefono', 'email', 'experiencia', 'ciudad', 'grado_academico', 'observaciones']:
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
            
    except Exception as e: 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()

@app.route('/api/vacancies', methods=['GET', 'POST'])
@token_required
def handle_vacancies():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Vacantes WHERE id_cliente = %s ORDER BY fecha_publicacion DESC", (tenant_id,))
            return jsonify(cursor.fetchall())
            
        elif request.method == 'POST':
            data = request.get_json()
            sql = """
                INSERT INTO Vacantes (cargo_solicitado, descripcion, requisitos, salario, ciudad, estado, fecha_publicacion, id_cliente) 
                VALUES (%s, %s, %s, %s, %s, 'Abierta', NOW(), %s)
            """
            cursor.execute(sql, (data['cargo_solicitado'], data['descripcion'], data['requisitos'], data['salario'], data['ciudad'], tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Vacante creada exitosamente."})
            
    except Exception as e: 
        conn.rollback(); 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()

@app.route('/api/vacancies/<int:id_vacante>/status', methods=['PUT'])
@token_required
def update_vacancy_status(id_vacante):
    data = request.get_json()
    new_status = data.get('status')
    
    if new_status not in ['Abierta', 'Cerrada', 'Pausada']:
        return jsonify({"error": "Estado inválido"}), 400
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor()
    
    try:
        tenant_id = get_current_tenant_id()
        cursor.execute("UPDATE Vacantes SET estado = %s WHERE id_vacante = %s AND id_cliente = %s", (new_status, id_vacante, tenant_id))
        
        if cursor.rowcount == 0:
            return jsonify({"error": "Vacante no encontrada"}), 404
            
        conn.commit()
        return jsonify({"success": True, "message": f"Estado actualizado a {new_status}"})
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/vacancies/active', methods=['GET'])
@token_required
def get_active_vacancies():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de BD"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        cursor.execute("SELECT * FROM Vacantes WHERE estado = 'Abierta' AND id_cliente = %s", (tenant_id,))
        return jsonify(cursor.fetchall())
    except Exception as e: 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()

@app.route('/api/applications', methods=['GET','POST'])
@token_required
def handle_applications():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("""
                SELECT p.*, a.nombre_completo, a.telefono, a.email, a.cv_url, v.cargo_solicitado, c.empresa
                FROM Postulaciones p
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE p.id_cliente = %s
                ORDER BY p.fecha_aplicacion DESC
            """, (tenant_id,))
            return jsonify(cursor.fetchall())
            
        elif request.method == 'POST':
            data = request.get_json()
            
            # Verificar que el afiliado y la vacante pertenecen al tenant
            cursor.execute("SELECT id_afiliado FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (data['id_afiliado'], tenant_id))
            if not cursor.fetchone():
                return jsonify({"error": "Afiliado no encontrado"}), 404
                
            cursor.execute("SELECT id_vacante FROM Vacantes WHERE id_vacante = %s AND id_cliente = %s", (data['id_vacante'], tenant_id))
            if not cursor.fetchone():
                return jsonify({"error": "Vacante no encontrada"}), 404
            
            # Verificar duplicados
            cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_afiliado = %s AND id_vacante = %s AND id_cliente = %s", 
                         (data['id_afiliado'], data['id_vacante'], tenant_id))
            if cursor.fetchone():
                return jsonify({"error": "El candidato ya ha postulado a esta vacante"}), 400
            
            sql = """
                INSERT INTO Postulaciones (id_afiliado, id_vacante, fecha_aplicacion, estado, comentarios, id_cliente) 
                VALUES (%s, %s, NOW(), 'Recibida', %s, %s)
            """
            cursor.execute(sql, (data['id_afiliado'], data['id_vacante'], data.get('comentarios', ''), tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Postulación registrada exitosamente."})
            
    except Exception as e: 
        conn.rollback(); 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()

@app.route('/api/applications/<int:id_postulacion>', methods=['DELETE'])
@token_required
def delete_application(id_postulacion):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor()
    
    try:
        tenant_id = get_current_tenant_id()
        
        # Verificar que la postulación pertenece al tenant
        cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (id_postulacion, tenant_id))
        if not cursor.fetchone():
            return jsonify({"error": "Postulación no encontrada"}), 404
        
        # Eliminar entrevistas relacionadas primero
        cursor.execute("DELETE FROM Entrevistas WHERE id_postulacion = %s", (id_postulacion,))
        
        # Eliminar la postulación
        cursor.execute("DELETE FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (id_postulacion, tenant_id))
        
        conn.commit()
        return jsonify({"success": True, "message": "Postulación eliminada exitosamente."})
        
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/interviews', methods=['GET', 'POST'])
@token_required
def handle_interviews():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("""
                SELECT e.*, p.id_afiliado, a.nombre_completo, v.cargo_solicitado, c.empresa
                FROM Entrevistas e
                JOIN Postulaciones p ON e.id_postulacion = p.id_postulacion
                JOIN Afiliados a ON p.id_afiliado = a.id_afiliado
                JOIN Vacantes v ON p.id_vacante = v.id_vacante
                JOIN Clientes c ON v.id_cliente = c.id_cliente
                WHERE e.id_cliente = %s
                ORDER BY e.fecha_hora DESC
            """, (tenant_id,))
            return jsonify(cursor.fetchall())
            
        elif request.method == 'POST':
            data = request.get_json()
            
            # Verificar que la postulación pertenece al tenant
            cursor.execute("SELECT id_postulacion FROM Postulaciones WHERE id_postulacion = %s AND id_cliente = %s", (data['id_postulacion'], tenant_id))
            if not cursor.fetchone():
                return jsonify({"error": "Postulación no encontrada"}), 404
            
            sql = """
                INSERT INTO Entrevistas (id_postulacion, fecha_hora, entrevistador, resultado, observaciones, id_cliente) 
                VALUES (%s, %s, %s, 'Programada', %s, %s)
            """
            cursor.execute(sql, (data['id_postulacion'], data['fecha_hora'], data['entrevistador'], data.get('observaciones', ''), tenant_id))
            
            # Actualizar estado de postulación
            cursor.execute("UPDATE Postulaciones SET estado = 'En Entrevista' WHERE id_postulacion = %s AND id_cliente = %s", (data['id_postulacion'], tenant_id))
            
            conn.commit()
            return jsonify({"success": True, "message": "Entrevista programada exitosamente."})
            
    except Exception as e: 
        conn.rollback(); 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()

@app.route('/api/tags', methods=['GET', 'POST'])
@token_required
def handle_tags():
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        if request.method == 'GET':
            cursor.execute("SELECT * FROM Tags WHERE id_cliente = %s ORDER BY nombre_tag", (tenant_id,))
            return jsonify(cursor.fetchall())
            
        elif request.method == 'POST':
            data = request.get_json()
            cursor.execute("INSERT INTO Tags (nombre_tag, descripcion, id_cliente) VALUES (%s, %s, %s)", 
                         (data['nombre_tag'], data.get('descripcion', ''), tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Etiqueta creada exitosamente."})
            
    except Exception as e: 
        conn.rollback(); 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()

@app.route('/api/candidate/<int:id_afiliado>/tags', methods=['GET', 'POST', 'DELETE'])
@token_required
def handle_candidate_tags(id_afiliado):
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Error de conexión"}), 500
    cursor = conn.cursor(dictionary=True)
    try:
        tenant_id = get_current_tenant_id()
        
        # Verificar que el afiliado pertenece al tenant
        cursor.execute("SELECT id_afiliado FROM Afiliados WHERE id_afiliado = %s AND id_cliente = %s", (id_afiliado, tenant_id))
        if not cursor.fetchone():
            return jsonify({"error": "Candidato no encontrado"}), 404
        
        if request.method == 'GET':
            cursor.execute("""
                SELECT t.id_tag, t.nombre_tag 
                FROM Tags t 
                JOIN Afiliado_Tags at ON t.id_tag = at.id_tag 
                WHERE at.id_afiliado = %s AND t.id_cliente = %s
            """, (id_afiliado, tenant_id))
            return jsonify(cursor.fetchall())
            
        elif request.method == 'POST':
            data = request.get_json()
            id_tag = data.get('id_tag')
            
            # Verificar que el tag pertenece al tenant
            cursor.execute("SELECT id_tag FROM Tags WHERE id_tag = %s AND id_cliente = %s", (id_tag, tenant_id))
            if not cursor.fetchone():
                return jsonify({"error": "Etiqueta no encontrada"}), 404
            
            cursor.execute("INSERT IGNORE INTO Afiliado_Tags (id_afiliado, id_tag, id_cliente) VALUES (%s, %s, %s)", 
                         (id_afiliado, id_tag, tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Etiqueta asignada."})
            
        elif request.method == 'DELETE':
            data = request.get_json()
            id_tag = data.get('id_tag')
            cursor.execute("DELETE FROM Afiliado_Tags WHERE id_afiliado = %s AND id_tag = %s AND id_cliente = %s", 
                         (id_afiliado, id_tag, tenant_id))
            conn.commit()
            return jsonify({"success": True, "message": "Etiqueta removida."})
            
    except Exception as e: 
        conn.rollback(); 
        return jsonify({"error": str(e)}), 500
    finally: 
        cursor.close(); conn.close()
