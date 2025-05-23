import random
from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.contrib.auth import login, logout, authenticate
import pyrebase
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from .forms import NivelForm, CursoForm
from django.http import JsonResponse
import json
from django.contrib import messages
from django.http import JsonResponse
import smtplib
from email.mime.text import MIMEText
from django.shortcuts import render, redirect
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib.auth.forms import AuthenticationForm
from django.utils.datastructures import MultiValueDictKeyError
import random
import smtplib
import re
from django.http import JsonResponse
from django.core.mail import send_mail
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt
import io
import urllib, base64
import io
import base64
import matplotlib.pyplot as plt
from django.shortcuts import render, redirect
import numpy as np
import pandas as pd
import firebase_admin
from firebase_admin import credentials, db
from django.shortcuts import redirect
import joblib
import tensorflow as tf
import pandas as pd
from django.utils.html import escape
from jwcrypto.jwk import JWK
verification_code = None
config = {
  'apiKey' : "AIzaSyCTUlvIT0XHd7Bqn5L4MbGTaXKN58hBOc8",
  'authDomain' : "mindvoyager-67287.firebaseapp.com",
  'projectId' : "mindvoyager-67287",
  'databaseURL': "https://mindvoyager-67287-default-rtdb.firebaseio.com",
  'storageBucket' : "mindvoyager-67287.appspot.com",
  'messagingSenderId' : "448352163680",
  'appId' : "1:448352163680:web:b928bbfb1f6c72296a7005",
  'measurementId': "G-J5R8HF3M23"
}
firebase = pyrebase.initialize_app(config)
storage = firebase.storage()
def connectDB(table):
    if not firebase_admin._apps:
        cred = credentials.Certificate("crud_DJ\\mindvoyager-67287-firebase-adminsdk-n96en-ece0d7cd30.json")
        firebase_admin.initialize_app(cred, {
            "databaseURL": "https://mindvoyager-67287-default-rtdb.firebaseio.com/" #Your database URL
        })
    dbconn = db.reference(table)       
    return dbconn
def initialize_firebase():
    if not firebase_admin._apps:
        cred = credentials.Certificate("crud_DJ/mindvoyager-67287-firebase-adminsdk-n96en-ece0d7cd30.json")
        firebase_admin.initialize_app(cred, {
            "databaseURL": "https://mindvoyager-67287-default-rtdb.firebaseio.com/"
        })
def home(request):
   return render(request, "home.html")
from django.http import JsonResponse
model_path = "crud_DJ\\tasks\\static\\IA\\personality_disorder_prediction_model.h5"
scaler_path = "crud_DJ\\tasks\\static\\IA\\scaler_trastornos_personalidad.save"
model = tf.keras.models.load_model(model_path)
scaler = joblib.load(scaler_path)
def update_probabilities():
    dbconn = connectDB("Cursos")
    cursos_ref = dbconn.get()  

    if cursos_ref:
        for curso_key, curso_value in cursos_ref.items():
            estudiantes_ref = dbconn.child(curso_key).child("Estudiantes").get()
            
            if estudiantes_ref:
                for estudiante_key, estudiante_value in estudiantes_ref.items():

                    comportamientos = dbconn.child(curso_key).child("Estudiantes").child(estudiante_key).child("Comportamientos").get()
                    
                    if comportamientos:
                        # Extrae los datos de comportamiento actuales del estudiante
                        agresividad = comportamientos.get('Agresividad', 0)
                        impulsividad = comportamientos.get('Impulsividad', 0)
                        narcisismo = comportamientos.get('Narcisismo', 0)
                        paranoia = comportamientos.get('Paranoia', 0)
                        tlp = comportamientos.get('TLP', 0)

                        # Revisa las probabilidades previas en Firebase para el estudiante
                        probabilidades_actuales = dbconn.child(curso_key).child("Estudiantes").child(estudiante_key).child("Probabilidades").get()
                        
                        # Solo calcula si alguna probabilidad o valor cambió
                        recalcular = False
                        if probabilidades_actuales:
                            # Comparar valores anteriores con los actuales
                            if (probabilidades_actuales.get("Agresividad", 0) != agresividad or
                                probabilidades_actuales.get("Impulsividad", 0) != impulsividad or
                                probabilidades_actuales.get("Narcisismo", 0) != narcisismo or
                                probabilidades_actuales.get("Paranoia", 0) != paranoia or
                                probabilidades_actuales.get("TLP", 0) != tlp):
                                recalcular = True
                        else:
                            # Si no hay probabilidades guardadas, calcularlas
                            recalcular = True

                        if recalcular:
                            datos_entrada = np.array([[agresividad, impulsividad, narcisismo, paranoia, tlp]], dtype=np.float32)
                            
                            # Escala los datos de entrada
                            try:
                                datos_entrada_escalados = scaler.transform(datos_entrada)
                            except Exception as e:
                                print(f"Error al escalar datos para el estudiante {estudiante_key}: {e}")
                                continue

                            # Realiza la predicción individual para cada estudiante
                            predicciones = model.predict(datos_entrada_escalados)

                            # Extrae y ajusta las probabilidades aplicando el porcentaje de descuento
                            prob1año = (float(predicciones[0][0]) * 100) * 0.9  # Aplica descuento del 10%
                            prob3año = (float(predicciones[0][1]) * 100) * 0.85  # Aplica descuento del 15%
                            prob5año = (float(predicciones[0][2]) * 100) * 0.8  # Aplica descuento del 20%

                            # Actualiza las probabilidades en Firebase
                            dbconn.child(curso_key).child("Estudiantes").child(estudiante_key).child("Probabilidades").set({
                                "Prob1Año": prob1año,
                                "Prob3Año": prob3año,
                                "Prob5Año": prob5año,
                                # Guarda también los valores actuales de comportamiento
                                "Agresividad": agresividad,
                                "Impulsividad": impulsividad,
                                "Narcisismo": narcisismo,
                                "Paranoia": paranoia,
                                "TLP": tlp
                            })

                            # Verificación en consola para cada estudiante
                            print(f"Estudiante {estudiante_key} - Probabilidades ajustadas: 1 Año: {prob1año}%, 3 Años: {prob3año}%, 5 Años: {prob5año}%")
                        else:
                            print(f"Estudiante {estudiante_key} - Sin cambios en comportamientos, no se recalcula")
                    else:
                        print(f"No se encontraron datos de comportamientos para el estudiante {estudiante_key}")
private_key = JWK.generate(kty='RSA', size=2048)
import re
from django.http import JsonResponse
def clean_ci(ci_value):
    return re.sub(r'\D+', '', ci_value)
def verify_ci(request, estudiante_id, ci_digits):
    # Conectar a la base de datos
    dbconn = connectDB("Cursos")
    cursos = dbconn.get()

    # Buscar el estudiante por su ID
    for curso_key, curso in cursos.items():
        estudiantes = curso.get("Estudiantes", {})

        if estudiante_id in estudiantes:
            # Obtener los datos del estudiante
            estudiante = estudiantes[estudiante_id]
            estudiante_ci = estudiante.get('CI', '')

            # Limpiar y normalizar los CIs
            estudiante_ci = clean_ci(str(estudiante_ci).strip())
            ci_digits = clean_ci(str(ci_digits).strip())

            # Verificar que el CI coincida
            if estudiante_ci == ci_digits:
                # CI correcto, responder con éxito
                return JsonResponse({'valid': True, 'message': 'CI verificado correctamente.'})
            else:
                # CI incorrecto
                return JsonResponse({'valid': False, 'message': 'CI incorrecto.'})

    # Si no se encontró el estudiante
    return JsonResponse({'valid': False, 'message': 'Estudiante no encontrado.'})
from firebase_admin import auth  # Asegúrate de importar Firebase Authentication SDK
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
AES_KEY = bytes.fromhex("6b85bfc04e173e3d37d1eb4e604dc777beba39e945a03c0f6881871b417eddbc")
AES_IV = bytes.fromhex("f865962cf7c6685175473cf9ef2f7628")
def encrypt_password(password):
    """Cifra la contraseña usando AES en modo CBC."""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=backend)
    encryptor = cipher.encryptor()

    # Aplicar padding a la contraseña
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_password = padder.update(password.encode('utf-8')) + padder.finalize()

    # Cifrar y codificar en base64
    encrypted = encryptor.update(padded_password) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')
def decrypt_password(encrypted_password):
    """Descifra una contraseña encriptada usando AES en modo CBC."""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=backend)
    decryptor = cipher.decryptor()

    # Decodificar desde base64 y descifrar
    encrypted_data = base64.b64decode(encrypted_password)
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    # Remover padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode('utf-8')
def signup(request):
    if request.method == 'GET':
        dbconn = connectDB("Cursos")
        cursos = dbconn.get()
        estudiantes = []

        # Filtrar estudiantes que no tienen el campo 'Contraseña'
        for curso in cursos.values():
            for estudiante_id, estudiante in curso.get("Estudiantes", {}).items():
                if 'Contraseña' not in estudiante or not estudiante['Contraseña']:
                    estudiante['id'] = estudiante_id  # Añadimos el ID del estudiante
                    estudiantes.append(estudiante)

        return render(request, 'signup.html', {
            'form': AuthenticationForm,
            'estudiantes': estudiantes,  # Lista de estudiantes filtrados para el template
        })

    elif request.method == 'POST':
        # Obtener los datos del formulario
        estudiante_id = request.POST.get("nombre_estudiante")
        direccion = request.POST.get("address")
        telefono = request.POST.get("telefono")
        gmail = request.POST.get("email")
        edad = request.POST.get("age")
        genero = request.POST.get("gender")
        contraseña = request.POST.get("password1")
        confirmacion_contraseña = request.POST.get("password2")

        # Verificar que las contraseñas coinciden
        if contraseña != confirmacion_contraseña:
            return render(request, 'signup.html', {
                'form': AuthenticationForm,
                'error': 'Las contraseñas no coinciden.',
            })

        # Cifrar la contraseña antes de guardarla
        contraseña_cifrada = encrypt_password(contraseña)

        # Conectar a la base de datos y buscar el estudiante
        dbconn = connectDB("Cursos")
        cursos = dbconn.get()

        for curso_key, curso in cursos.items():
            estudiantes = curso.get("Estudiantes", {})

            if estudiante_id in estudiantes:
                # Actualizar los datos del estudiante
                estudiante = estudiantes[estudiante_id]
                estudiante['Direccion'] = direccion
                estudiante['Telefono'] = telefono
                estudiante['Gmail'] = gmail
                estudiante['edad'] = edad
                estudiante['genero'] = genero
                estudiante['Contraseña'] = contraseña_cifrada  # Guardar la contraseña cifrada

                # Guardar los cambios en Firebase Database
                dbconn.child(f"{curso_key}/Estudiantes/{estudiante_id}").set(estudiante)

                # Crear usuario en Firebase Authentication
                try:
                    user = auth.create_user(
                        email=gmail,
                        password=contraseña
                    )
                    # Puedes almacenar el UID generado por Firebase Auth en tu base de datos si lo necesitas
                    estudiante['UID'] = user.uid
                    dbconn.child(f"{curso_key}/Estudiantes/{estudiante_id}").set(estudiante)

                    # Redirigir o mostrar un mensaje de éxito
                    return render(request, 'signup.html', {
                        'form': AuthenticationForm,
                        'success': 'Estudiante registrado y autenticado exitosamente.',
                    })
                except Exception as e:
                    return render(request, 'signup.html', {
                        'form': AuthenticationForm,
                        'error': f'Error al registrar el usuario en autenticación: {str(e)}',
                    })

        # Si no se encontró el estudiante, devolver un error
        return render(request, 'signup.html', {
            'form': AuthenticationForm,
            'error': 'Estudiante no encontrado.',
        })

    # Respuesta predeterminada para cualquier otro caso
    return render(request, 'signup.html', {
        'form': AuthenticationForm,
        'error': 'Método de solicitud no soportado.',
    })
def get_estudiante_info(request, estudiante_id):
    dbconn = connectDB("Cursos")
    cursos = dbconn.get()

    for curso in cursos.values():
        estudiantes = curso.get("Estudiantes", {})

        if estudiante_id in estudiantes:
            estudiante = estudiantes[estudiante_id]
            # Enviar los datos en minúsculas para coincidir con los nombres en el script de JavaScript
            return JsonResponse({
                "direccion": estudiante.get("Direccion", ""),
                "telefono": estudiante.get("Telefono", ""),
                "gmail": estudiante.get("Gmail", ""),
                "edad": estudiante.get("edad", ""),
                "genero": estudiante.get("genero", ""),
            })

    return JsonResponse({"error": "Estudiante no encontrado"}, status=404)
def task(request):
    # Verificar si el usuario tiene un rol en la sesión
    if 'role' in request.session and 'user_id' in request.session:
        role = request.session.get('role')  # Obtener el rol de la sesión
        user_id = request.session.get('user_id')  # Obtener el id de usuario de la sesión (Firebase ID)
        username = None

        # Buscar según el rol
        if role == 'estudiante':
            # Buscar el nombre del estudiante directamente en la rama "Cursos" usando el ID de Firebase
            dbconn = connectDB('Cursos')
            cursos = dbconn.get()
            for curso_id, curso_data in cursos.items():
                estudiantes = curso_data.get("Estudiantes", {})
                # Buscar al estudiante directamente usando el ID de Firebase
                estudiante_data = estudiantes.get(user_id)
                if estudiante_data:
                    username = estudiante_data.get("nombre")
                    break

        elif role == 'administrativo':
            # Buscar el nombre del administrativo directamente usando el ID de Firebase
            dbconn_admin = connectDB('Administrativos')
            administrativo_data = dbconn_admin.get().get(user_id)
            if administrativo_data:
                username = administrativo_data.get("Nombre")

        if username:
            return render(request, 'task.html', {'role': role, 'username': username})

    # Si no hay rol en la sesión o no se encuentra el usuario, redirigir a la página de inicio de sesión
    return redirect('signin')
def Cursos(request):
  if 'role' in request.session and request.session['role'] == 'administrativo': 
    return render(request, 'Cursos.html')
  return redirect('signin')
def Estudiantes(request):
  if 'role' in request.session and request.session['role'] == 'administrativo':   
    return render(request, 'Estudiantes.html')
  return redirect('signin')
def miPerfil(request):
    # Verificar si el usuario tiene un rol en la sesión
    if 'role' in request.session and 'user_id' in request.session:
        role = request.session.get('role')  # Obtener el rol de la sesión
        user_id = request.session.get('user_id')  # Obtener el id de usuario de la sesión (Firebase ID)
        username = None
        genero = None
        Telefono = None
        Gmail = None
        Direccion = None
        
        # Recuperar los datos del usuario basado en el rol
        if role == 'estudiante':
            # Buscar los datos del estudiante directamente en la rama "Cursos" usando el ID de Firebase
            dbconn = connectDB('Cursos')
            cursos = dbconn.get()
            for curso_id, curso_data in cursos.items():
                estudiantes = curso_data.get("Estudiantes", {})
                # Buscar al estudiante directamente usando el ID de Firebase
                estudiante_data = estudiantes.get(user_id)
                if estudiante_data:
                    username = estudiante_data.get("nombre")
                    genero = estudiante_data.get("genero")
                    Telefono = estudiante_data.get("Telefono")
                    Gmail = estudiante_data.get("Gmail")
                    Direccion = estudiante_data.get("Direccion")
                    break

        elif role == 'administrativo':
            # Buscar los datos del administrativo directamente usando el ID de Firebase
            dbconn_admin = connectDB('Administrativos')
            administrativo_data = dbconn_admin.get().get(user_id)
            if administrativo_data:
                username = administrativo_data.get("Nombre")
                genero = administrativo_data.get("genero")
                Telefono = administrativo_data.get("Telefono")
                Gmail = administrativo_data.get("Gmail")
                Direccion = administrativo_data.get("Direccion")

        # Si se encuentra el usuario, renderizar la página del perfil
        if username:
            return render(request, 'miperfil.html', {
                'role': role,
                'username': username,
                'genero': genero,
                'Telefono': Telefono,
                'Gmail': Gmail,
                'Direccion': Direccion
            })

    # Si no hay rol en la sesión o no se encuentra el usuario, redirigir a la página de inicio de sesión
    return redirect('signin')
def update_profile(request):
    if request.method == 'POST':
        try:
            # Obtener los datos enviados en el request
            data = json.loads(request.body)
            telefono = data.get('Telefono')
            gmail = data.get('Gmail')
            direccion = data.get('Direccion')
            user_id = request.session.get('user_id')  # Obtener el id de usuario de la sesión (Firebase ID)
            role = request.session.get('role')  # Obtener el rol del usuario de la sesión

            # Conectar a Firebase y actualizar los datos del usuario según su rol
            if role == 'estudiante':
                dbconn = connectDB('Cursos')
                cursos = dbconn.get()
                for curso_id, curso_data in cursos.items():
                    estudiantes = curso_data.get("Estudiantes", {})
                    # Buscar al estudiante directamente usando el ID de Firebase
                    estudiante_data = estudiantes.get(user_id)
                    if estudiante_data:
                        # Actualizar los datos del estudiante
                        dbconn.child(curso_id).child("Estudiantes").child(user_id).update({
                            "Telefono": telefono,
                            "Gmail": gmail,
                            "Direccion": direccion
                        })
                        break
            elif role == 'administrativo':
                dbconn_admin = connectDB('Administrativos')
                # Buscar al administrativo directamente usando el ID de Firebase
                administrativo_data = dbconn_admin.get().get(user_id)
                if administrativo_data:
                    # Actualizar los datos del administrativo
                    dbconn_admin.child(user_id).update({
                        "Telefono": telefono,
                        "Gmail": gmail,
                        "Direccion": direccion
                    })

            # Devolver respuesta de éxito
            return JsonResponse({"success": True})
        except Exception as e:
            print(f"Error actualizando perfil: {e}")
            return JsonResponse({"success": False})

    # Si el método no es POST, devolver respuesta de error
    return JsonResponse({"success": False})
def Resumen(request):
    if 'role' in request.session and request.session['role'] == 'administrativo':
        dbconn = connectDB("Cursos")
        data = dbconn.get()
        cursos = []
        promedios_cursos = {}  # Para almacenar los promedios por curso

        if data:
            for curso_id, curso_data in data.items():
                if isinstance(curso_data, dict):
                    curso_nombre = curso_data.get("Nombre", "Curso sin nombre")
                    estudiantes = curso_data.get("Estudiantes", {})
                    lista_estudiantes = []
                    total_prob_1 = total_prob_3 = total_prob_5 = 0
                    count_estudiantes = len(estudiantes)

                    # Validar si el curso tiene estudiantes
                    if count_estudiantes > 0:
                        for estudiante_id, estudiante_data in estudiantes.items():
                            nombre_estudiante = estudiante_data.get("nombre", "Nombre no encontrado")
                            probabilidades = estudiante_data.get("Probabilidades", {})
                            prob_1_año = probabilidades.get("Prob1Año", 0)
                            prob_3_años = probabilidades.get("Prob3Año", 0)
                            prob_5_años = probabilidades.get("Prob5Año", 0)

                            total_prob_1 += prob_1_año
                            total_prob_3 += prob_3_años
                            total_prob_5 += prob_5_años

                            lista_estudiantes.append({
                                "nombre": nombre_estudiante,
                                "prob_1_año": prob_1_año,
                                "prob_3_años": prob_3_años,
                                "prob_5_años": prob_5_años,
                            })

                        # Calcular el promedio de probabilidades para el curso
                        promedio_curso = (total_prob_1 + total_prob_3 + total_prob_5) / (count_estudiantes * 3)
                        promedios_cursos[curso_nombre] = promedio_curso

                        # Generar gráficos específicos para cada curso
                        grafico_1_año = generar_grafico_base64(curso_nombre, lista_estudiantes, 1)
                        grafico_3_años = generar_grafico_base64(curso_nombre, lista_estudiantes, 3)
                        grafico_5_años = generar_grafico_base64(curso_nombre, lista_estudiantes, 5)

                        cursos.append({
                            "nombre": curso_nombre,
                            "grafico_1_año": grafico_1_año,
                            "grafico_3_años": grafico_3_años,
                            "grafico_5_años": grafico_5_años,
                        })

        # Generar gráficos de comparación
        grafico_barras_promedios = generar_grafico_barras_promedios(promedios_cursos)
        grafico_lineas_promedios = generar_grafico_lineas_promedios(promedios_cursos)

        return render(request, 'Resumen.html', {
            "cursos": cursos,
            "grafico_barras_promedios": grafico_barras_promedios,
            "grafico_lineas_promedios": grafico_lineas_promedios
        })

    return redirect('signin')
# Nueva función para generar el gráfico de barras comparativo
def generar_grafico_barras_promedios(promedios_cursos):
    nombres_cursos = list(promedios_cursos.keys())
    valores_promedios = list(promedios_cursos.values())

    plt.figure(figsize=(10, 5))
    plt.bar(nombres_cursos, valores_promedios, color='#2196f3')
    plt.title("Promedio de Probabilidades por Curso")
    plt.xlabel("Cursos")
    plt.ylabel("Promedio de Probabilidad (%)")
    plt.ylim(0, 100)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format="png")
    plt.close()
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    buffer.close()

    return f"data:image/png;base64,{image_base64}"
# Nueva función para generar el gráfico de líneas comparativo
def generar_grafico_lineas_promedios(promedios_cursos):
    nombres_cursos = list(promedios_cursos.keys())
    valores_promedios = list(promedios_cursos.values())

    # Ordenar los cursos del año más reciente al más antiguo
    nombres_cursos, valores_promedios = zip(*sorted(zip(nombres_cursos, valores_promedios), reverse=True))

    plt.figure(figsize=(10, 5))
    plt.plot(nombres_cursos, valores_promedios, marker='o', color='#4caf50', linestyle='-')
    plt.title("Comparativa de Probabilidades (de reciente a antiguo)")
    plt.xlabel("Cursos")
    plt.ylabel("Promedio de Probabilidad (%)")
    plt.ylim(0, 100)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format="png")
    plt.close()
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    buffer.close()

    return f"data:image/png;base64,{image_base64}"
# Función para generar gráficos en base64
def generar_grafico_base64(curso_nombre, estudiantes, anio):
    nombres = [est['nombre'] for est in estudiantes]
    
    # Ajustar el nombre de la clave de acuerdo al número de años
    prob_key = f'prob_{anio}_años' if anio > 1 else f'prob_{anio}_año'
    probabilidades = [est.get(prob_key, 0) for est in estudiantes]
    
    plt.figure(figsize=(10, 5))
    plt.bar(nombres, probabilidades, color='#6a1b9a')
    plt.title(f"{curso_nombre} - Probabilidad de {anio} Año(s)")
    plt.xlabel("Estudiantes")
    plt.ylabel("Probabilidad (%)")
    plt.ylim(0, 100)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    
    # Convertir gráfico a base64
    buffer = io.BytesIO()
    plt.savefig(buffer, format="png")
    plt.close()
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
    buffer.close()
    
    return f"data:image/png;base64,{image_base64}"
def CasosCriticos(request):
    if 'role' in request.session and request.session['role'] == 'administrativo':  
        dbconn = connectDB("Cursos")
        cursos_ref = dbconn.get()  # Obtiene todos los cursos
        
        estudiantes = []
        
        if cursos_ref:
            for key, value in cursos_ref.items():
                estudiantes_ref = dbconn.child(key).child("Estudiantes").get()
                if estudiantes_ref:
                    for estudiante_key, estudiante_value in estudiantes_ref.items():
                        probabilidad_1año = estudiante_value.get("Probabilidades", {}).get("Prob1Año", 0)
                        if probabilidad_1año > 40:
                            estudiantes.append({
                                "id": estudiante_key,
                                "nombre": estudiante_value.get("nombre"),
                                "CI": estudiante_value.get("CI"),
                                "edad": estudiante_value.get("edad"),
                                "genero": estudiante_value.get("genero"),
                                "estado": estudiante_value.get("estado"),
                                "Telefono": estudiante_value.get("Telefono"),
                                "Gmail": estudiante_value.get("Gmail"),
                                "Direccion": estudiante_value.get("Direccion"),
                                "probabilidad_1año": probabilidad_1año  # Incluimos este campo en el contexto
                            })
        
        return render(request, 'CasosCriticos.html', {
            'estudiantes': estudiantes
        })
    return redirect('signin')
def signout(request):
  logout(request)
  return redirect('home')
private_key = JWK.generate(kty='RSA', size=2048)
from datetime import timedelta
from jwcrypto.jwk import JWK
from django.shortcuts import render, redirect
from django.http import JsonResponse
# Función para firmar un JWT
def generate_jwt(claims, lifetime=timedelta(hours=1)):
    from jwcrypto.jwt import JWT
    import datetime

    token = JWT(header={"alg": "RS256"}, claims={
        **claims,
        "exp": int((datetime.datetime.utcnow() + lifetime).timestamp())
    })
    token.make_signed_token(private_key)
    return token.serialize()
from django.shortcuts import render, redirect
from django.http import JsonResponse
from jwcrypto.jwk import JWK
from datetime import timedelta
from jwcrypto.jwt import JWT
private_key = JWK.generate(kty='RSA', size=2048)
def generate_jwt(claims, lifetime=timedelta(hours=1)):
    import datetime
    token = JWT(
        header={"alg": "RS256"},
        claims={
            **claims,
            "exp": int((datetime.datetime.utcnow() + lifetime).timestamp())
        }
    )
    token.make_signed_token(private_key)
    return token.serialize()
def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        role = request.POST['role']  # Obtenemos el rol del formulario

        # Validar el rol de usuario
        if role == "administrativo":
            dbconn = connectDB("Administrativos")
            administrativos = dbconn.get()
            for key, administrativo in administrativos.items():
                if (
                    administrativo["Gmail"] == username and
                    administrativo["Estado"] == "Activo"
                ):
                    try: 
                         decrypted_password = decrypt_password(administrativo["Contraseña"])
                         if decrypted_password == password:
                    # Generar el token JWT para el usuario administrativo
                          claims = {
                           "user_id": key,
                           "role": "administrativo",
                           "username": username
                          }
                          jwt_token = generate_jwt(claims)

                    # Guardar la información en la sesión
                          request.session['role'] = 'administrativo'
                          request.session['user_id'] = key
                          request.session['jwt_token'] = jwt_token  # Guardar el token en la sesión

                          return redirect('task')  # Redirige a la vista de tareas
                    except Exception as e:
                     return render(request, 'signin.html', {
                        'error': f"Error al procesar la contraseña: {str(e)}"
                     })
        elif role == "estudiante":
            dbconn = connectDB("Cursos")
            cursos = dbconn.get()
            for curso_key, curso in cursos.items():
                estudiantes = curso.get("Estudiantes", {})
                for estudiante_key, estudiante in estudiantes.items():
                    if estudiante["Gmail"] == username:
                        try:
                            # Descifrar la contraseña almacenada
                            decrypted_password = decrypt_password(estudiante["Contraseña"])

                            # Validar la contraseña ingresada
                            if decrypted_password == password:
                                # Generar el token JWT para el usuario estudiante
                                claims = {
                                    "user_id": estudiante_key,
                                    "role": "estudiante",
                                    "username": username
                                }
                                jwt_token = generate_jwt(claims)

                                # Guardar la información en la sesión
                                request.session['role'] = 'estudiante'
                                request.session['user_id'] = estudiante_key
                                request.session['jwt_token'] = jwt_token  # Guardar el token en la sesión

                                return redirect('task')  # Redirige a la vista de tareas
                        except Exception as e:
                            return render(request, 'signin.html', {
                                'form': AuthenticationForm,
                                'error': f'Error al procesar la contraseña: {str(e)}'
                            })

        # Si la autenticación falla, muestra un error
        return render(request, 'signin.html', {
            'form': AuthenticationForm,
            'error': 'Usuario o contraseña incorrectos'
        })

    return render(request, 'signin.html', {'form': AuthenticationForm})
from django.shortcuts import render, redirect
def register_admin(request):
    table = "Administrativos"
    if request.method == 'POST':
        # Obtén los datos directamente desde request.POST
        Nombre = request.POST.get("admin_name")
        Direccion = request.POST.get("address_admin")
        Telefono = request.POST.get("telefono_admin")
        Email = request.POST.get("email_admin")
        Genero = request.POST.get("gender_admin")
        Contraseña = request.POST.get("password1_admin")

        # Cifrar la contraseña antes de guardarla
        Contraseña_cifrada = encrypt_password(Contraseña)

        # Aquí puedes agregar la validación de unicidad manualmente
        dbconn = connectDB(table)
       
        dbconn.push({
            "Nombre": Nombre,
            "Direccion": Direccion,
            "Telefono": Telefono,
            "Gmail": Email,
            "genero": Genero,
            "Contraseña": Contraseña_cifrada,  # Guardar la contraseña cifrada
            "Estado": "Inactivo"
        })
        return redirect('/signin')
    else:
        # Si es un método GET, mostramos el formulario vacío
        return render(request, 'signin.html')
def Niveles_juego(request):
    table = "Niveles_juego"
    cars = []
    dbconn = connectDB(table)
    data = dbconn.get()
    if data:
        for key, value in data.items():
            # Verifica que value sea un diccionario antes de acceder a sus claves
            if isinstance(value, dict):
                cars.append({"Id": value.get("Id"), "Nombre": value.get("Nombre"), "Estado": value.get("Estado")})
    else:
        print("No se encontraron datos en la base de datos.")
    estado_filtro = request.GET.get('estado')
    if estado_filtro:
        cars = [car for car in cars if car['Estado'] == estado_filtro]

    # Renderizar la respuesta con los datos obtenidos y el filtro seleccionado
    if 'role' in request.session and request.session['role'] == 'administrativo':   
     return render(request, 'Niveles.html', {
        "Niveles_juego": cars,
        "estado": estado_filtro  # Pasar el estado actual al template para mantener la selección
     })
    return redirect('signin')
def Detall_Niveles(request):
    table = "Niveles_juego"
    cars = []
    dbconn = connectDB(table)
    data = dbconn.get()
    if data:
        for key, value in data.items():
            if isinstance(value, dict):
                if value.get("Estado") == "Activo":
                    cars.append({
                        "Id": value.get("Id"),
                        "Nombre": value.get("Nombre"),
                        "Descripcion": value.get("Descripcion"),
                        "Historia": value.get("Historia"),
                        "Sugerencias": value.get("Sugerencias"),
                        "Estado": value.get("Estado")
                    })
    else:
        print("No se encontraron datos en la base de datos.")

    # Renderizar la respuesta con los niveles activos
    if 'role' in request.session and request.session['role'] == 'estudiante':   
        return render(request, 'Detall_Niveles.html', {
            "Niveles_juego": cars,
        })
    return redirect('signin')
def addNivel(request):
  if 'role' in request.session and request.session['role'] == 'administrativo':     
    table = "Niveles_juego"
    if request.method == 'GET':
        return render(request, 'Add_nivel.html')
    if request.method == 'POST':
        form = NivelForm(request.POST)
        if form.is_valid():
            Id = form.cleaned_data.get("Id")
            Nombre = form.cleaned_data.get("Nombre")
            Estado = form.cleaned_data.get("Estado")
        dbconn = connectDB(table)
        dbconn.push( { "Id": Id, "Nombre": Nombre, "Estado": Estado})
        return redirect('task')
  return redirect('signin')
def updatecar(request, Id):
  if 'role' in request.session and request.session['role'] == 'administrativo': 
    table = "Niveles_juego"
    dbconn = connectDB(table)  # Conexión a la base de datos de Firebase
    tblNiveles = dbconn.get()  # Obtener los datos de la base de datos

    if request.method == 'GET':
        # Buscar el nivel por el ID recibido
        for key, value in tblNiveles.items():
            if value["Id"] == Id:  # Asegurarse de comparar el Id como cadena
                global updatekey
                updatekey = key  # Guardar la clave del objeto que será actualizado
                nivel = {
                    "Id": value["Id"], 
                    "Nombre": value["Nombre"], 
                    "Estado": value["Estado"]
                }
                break
        else:
            return HttpResponse("No se encontró el nivel", status=404)

        # Renderizar el formulario con los datos actuales del nivel
        return render(request, 'Add_nivel.html', {'Nivel_juego': nivel})

    if request.method == 'POST':
        # Procesar el formulario de actualización
        form = NivelForm(request.POST)
        if form.is_valid():
            # Obtener los datos del formulario
            nombre = form.cleaned_data.get("Nombre")
            estado = form.cleaned_data.get("Estado")
            
            # Actualizar el objeto en Firebase usando la clave almacenada
            updateitem = dbconn.child(updatekey)
            updateitem.update({
                "Id": Id,  # Usar el Id existente
                "Nombre": nombre,
                "Estado": estado
            })
        return redirect('task') 
  return redirect('signin')
def ListarClase(request):
    if 'role' in request.session and request.session['role'] == 'administrativo':
        table = "Cursos"
        clases = []
        dbconn = connectDB(table)
        data = dbconn.get()
        # Obtener todos los años sin aplicar filtros
        todos_los_años = set()  # Usamos un set para evitar duplicados
        if data:
            for key, value in data.items():
                if isinstance(value, dict):
                    # Convertir el año a str antes de añadirlo al conjunto
                    año = value.get("año")
                    if año is not None:
                        todos_los_años.add(str(año))
        
        # Aplicar filtros
        estado = request.GET.get('estado', '')  # Filtrar por estado
        busqueda = request.GET.get('busqueda', '')  # Filtrar por búsqueda de texto (nombre o año)
        año_filtrado = request.GET.get('año', '')  # Filtrar por año
        if año_filtrado == '':  # Si el año es vacío o la opción de "Mostrar todos" está activa
            año_filtrado = None  # No aplicar filtro de año
        if data:
            for key, value in data.items():
                if isinstance(value, dict):
                    clase_año = value.get("año")
                    clase_nombre = value.get("Nombre")
                    clase_estado = value.get("Estado")
                    # Aplicar filtros de estado, búsqueda y año
                    if (not estado or clase_estado == estado) and \
                       (not año_filtrado or str(clase_año) == año_filtrado) and \
                       (not busqueda or busqueda.lower() in clase_nombre.lower() or busqueda.lower() in str(clase_año)):
                        clase = {
                            "Id": key,  # Usamos el ID generado por Firebase
                            "Nombre": clase_nombre,
                            "año": clase_año,
                            "Estado": clase_estado,
                            "Estudiantes": []  # Inicializa la lista de estudiantes
                        }

                        # Obtener estudiantes para la clase
                        estudiantes_ref = dbconn.child(key).child("Estudiantes").get()

                        if estudiantes_ref:
                            for estudiante_key, estudiante_value in estudiantes_ref.items():
                                clase["Estudiantes"].append({
                                    "Id": estudiante_key,  # Usamos el ID generado por Firebase para el estudiante
                                    "nombre": estudiante_value.get("nombre"),
                                    "edad": estudiante_value.get("edad")
                                })
                        
                        # Agregar la clase a la lista filtrada
                        clases.append(clase)

        # Calcular el total de estudiantes
        total_estudiantes = sum(len(clase["Estudiantes"]) for clase in clases)
        
        # Usar sorted() para ordenar los años, que ahora son todos str
        return render(request, 'Cursos.html', {
            "Clases": clases,
            "estado": estado,
            "busqueda": busqueda,
            "año": año_filtrado if año_filtrado else '',  # Enviar el año filtrado, o vacío si es None
            "todos_los_años": sorted(todos_los_años),  # Pasar todos los años disponibles al template
            "total_estudiantes": total_estudiantes
        })
    return redirect('signin')
def ver_estudiantes(request, id):
    if 'role' in request.session and request.session['role'] == 'administrativo': 
        # Para probar la función, simplemente llama a update_probabilities()
        update_probabilities() 
        dbconn = connectDB("Cursos")
        cursos_ref = dbconn.get()  # Obtiene todos los cursos
        curso_key = None
        clase_nombre = ""
        clase_año = ""
        if cursos_ref:
            for key, value in cursos_ref.items():
                if key == id:
                    if isinstance(value, dict):
                        clase_año = value.get("año")
                        clase_nombre = value.get("Nombre")
                    clase = {
                        "Id": key,
                        "Nombre": clase_nombre,
                        "año": clase_año,
                    }
                    curso_key = key
                    break

        estudiantes = []
        if curso_key:
            estudiantes_ref = dbconn.child(curso_key).child("Estudiantes").get()
            if estudiantes_ref:
                for estudiante_key, estudiante_value in estudiantes_ref.items():
                    estudiantes.append({
                        "id": estudiante_key,
                        "nombre": estudiante_value.get("nombre"),
                        "CI": estudiante_value.get("CI"),
                        "edad": estudiante_value.get("edad"),
                        "genero": estudiante_value.get("genero"),
                        "estado": estudiante_value.get("estado"),
                        "Telefono": estudiante_value.get("Telefono"),
                        "Gmail": estudiante_value.get("Gmail"),
                        "Direccion": estudiante_value.get("Direccion"),              
                    })

        # Obtener valores de búsqueda y filtro
        buscar_nombre = request.GET.get('buscar_nombre', '').lower()
        filtro_estado = request.GET.get('filtro_estado', 'todos').lower()

        # Filtrar estudiantes si hay criterios de búsqueda
        if buscar_nombre:
            estudiantes = [e for e in estudiantes if buscar_nombre in e['nombre'].lower()]
        if filtro_estado != 'todos':
            estudiantes = [e for e in estudiantes if e['estado'].lower() == filtro_estado]

        return render(request, 'Estudiantes.html', {
            'estudiantes': estudiantes, 
            'id': id, 
            'clase': clase,
            'buscar_nombre': buscar_nombre,
            'filtro_estado': filtro_estado,
        })
    return redirect('signin')
def archivar_estudiante(request, curso_id, estudiante_id):
    if request.method == 'POST' and 'role' in request.session and request.session['role'] == 'administrativo':
        dbconn = connectDB("Cursos")
        # Cambiar el estado del estudiante a "Inactivo"
        estudiante_ref = dbconn.child(curso_id).child("Estudiantes").child(estudiante_id)
        estudiante_ref.update({"estado": "Inactivo"})
        return JsonResponse({"success": True})
    return JsonResponse({"success": False}, status=400)
def editar_estudiante(request, curso_id, estudiante_id):
    if request.method == 'POST' and 'role' in request.session and request.session['role'] == 'administrativo':
        try:
            # Parsear datos enviados en el cuerpo de la solicitud
            data = json.loads(request.body)

            # Validar datos requeridos
            campos_requeridos = ['CI', 'nombre', 'edad', 'genero']
            if not all(campo in data for campo in campos_requeridos):
                return JsonResponse({"success": False, "message": "Datos incompletos"}, status=400)

            # Conectar a Firebase y actualizar datos
            dbconn = connectDB("Cursos")
            estudiante_ref = dbconn.child(curso_id).child("Estudiantes").child(estudiante_id)
            estudiante_ref.update({
                "CI": data['CI'],
                "nombre": data['nombre'],
                "edad": data['edad'],
                "genero": data['genero']
            })

            return JsonResponse({"success": True, "message": "Estudiante actualizado correctamente"})
        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=500)

    return JsonResponse({"success": False, "message": "Método no permitido o permisos insuficientes"}, status=400)
def cargar_datos_estudiante(request, curso_slug, estudiante_slug):
    if request.method == 'GET' and 'role' in request.session and request.session['role'] == 'administrativo':
        try:
            # Conectar a Firebase
            dbconn = connectDB("Cursos")
            estudiante_ref = dbconn.child(curso_slug).child("Estudiantes").child(estudiante_slug)
            estudiante_data = estudiante_ref.get()

            if estudiante_data:
                return JsonResponse({"success": True, "data": estudiante_data})
            else:
                return JsonResponse({"success": False, "message": "Estudiante no encontrado"}, status=404)
        except Exception as e:
            return JsonResponse({"success": False, "message": str(e)}, status=500)
    
    return JsonResponse({"success": False, "message": "Método no permitido o permisos insuficientes"}, status=400)
def restaurar_estudiante(request, curso_id, estudiante_id):
    if request.method == 'POST':
        dbconn = connectDB("Cursos")
        try:
            estudiante_ref = dbconn.child(curso_id).child("Estudiantes").child(estudiante_id)
            estudiante_ref.update({"estado": "Activo"})
            return JsonResponse({"success": True})
        except Exception as e:
            print(f"Error al restaurar el estudiante: {e}")
            return JsonResponse({"success": False})
    return JsonResponse({"success": False})
def addclase(request):
    # Verificamos que el usuario tenga el rol 'administrativo'
    if 'role' in request.session and request.session['role'] == 'administrativo':
        table = "Cursos"
        
        if request.method == 'POST':
            # Inicializamos el formulario con los datos enviados
            form = CursoForm(request.POST)
            
            if form.is_valid():
                # Obtener datos limpios del formulario
                Nombre = form.cleaned_data.get("Nombre")
                año = form.cleaned_data.get("año")
                Estado = form.cleaned_data.get("Estado")
                Nombre = escape(Nombre)
                año = escape(año)
                Estado = escape(Estado)

                # Conectar a Firebase
                dbconn = connectDB(table)

                try:
                    # Guardar datos en Firebase (sin ID manual)
                    dbconn.push({
                        "Nombre": Nombre,
                        "año": año,
                        "Estado": Estado
                    })
                    # Redirigir a la página de cursos si todo es exitoso
                    return redirect('../Cursos/')
                except Exception as e:
                    # Manejo de errores con Firebase
                    print(f"Error al guardar en Firebase: {e}")
                    return render(request, 'Add_clase.html', {'form': form, 'error': 'Error al guardar los datos.'})

            else:
                # Si el formulario no es válido, mostramos nuevamente el formulario con los errores
                return render(request, 'Add_clase.html', {'form': form})

        else:
            # Si es un método GET, mostramos el formulario vacío
            form = CursoForm()
            return render(request, 'Add_clase.html', {'form': form})

    # Si no tiene el rol adecuado, redirigir al inicio de sesión
    return redirect('signin')
def agregar_estudiante(request, id):
    if request.method == 'POST':
        # Obtenemos los datos del formulario y aplicamos sanitización con escape()
        nombre = escape(request.POST.get('nombre'))
        edad = escape(request.POST.get('edad'))
        genero = escape(request.POST.get('genero'))
        telefono = escape(request.POST.get('telefono'))
        gmail = escape(request.POST.get('gmail'))
        direccion = escape(request.POST.get('direccion'))
        CI = escape(request.POST.get('CI'))
        
        # Conectar a la base de datos Firebase
        dbconn = connectDB("Cursos")
        
        try:
            # Obtener el curso con el ID especificado
            curso_ref = dbconn.child(id).get()
            
            # Validar si el curso existe
            if not curso_ref:
                return redirect('ver_estudiantes', id=id)

            # Crear un nuevo estudiante con datos sanitizados y una colección inicial de comportamientos
            nuevo_estudiante = {
                'nombre': nombre,
                'edad': edad,
                'genero': genero,
                'Telefono': telefono,
                'Gmail': gmail,
                'Direccion': direccion,
                'CI': CI,
                'estado': 'Activo',
                'Comportamientos': {
                    'Impulsividad': 0,
                    'Paranoia': 0,
                    'Narcisismo': 0,
                    'TLP': 0,
                    'Agresividad': 0
                },
                'Probabilidades': {
                    'Prob1Año': 0,
                    'Prob3Año': 0,
                    'Prob5Año': 0
                }
            }

            # Guardar al estudiante bajo el curso especificado
            estudiantes_ref = dbconn.child(id).child('Estudiantes')
            estudiantes_ref.push(nuevo_estudiante)
        
        except Exception as e:
            # Manejo de errores al interactuar con Firebase
            print(f"Error al guardar estudiante en Firebase: {e}")
            return render(request, 'error.html', {'mensaje': 'Hubo un error al guardar los datos.'})

        # Redirigir a la página de los estudiantes si se guarda correctamente
        return redirect('ver_estudiantes', id=id)
    
    else:
        return redirect('ver_estudiantes', id=id)
def updateclase(request, Id):
    if 'role' in request.session and request.session['role'] == 'administrativo':      
        table = "Cursos"
        dbconn = connectDB(table) 
        tblCursos = dbconn.get()

        if request.method == 'GET':
            # Buscar el curso por el ID recibido
            for key, value in tblCursos.items():
                if key == Id:  # Asegurarse de comparar el Id como cadena
                    global updatekey
                    updatekey = key  # Guardar la clave del objeto que será actualizado
                    curso = {
                        "Nombre": value["Nombre"], 
                        "año": value["año"], 
                        "Estado": value["Estado"]
                    }
                    break
            else:
                return HttpResponse("No se encontró el curso", status=404)

            # Renderizar el formulario con los datos actuales del curso
            return render(request, 'Add_clase.html', {'clase': curso})

        if request.method == 'POST':
            # Procesar el formulario de actualización
            form = CursoForm(request.POST)
            if form.is_valid():
                # Obtener los datos del formulario
                nombre = form.cleaned_data.get("Nombre")
                año = form.cleaned_data.get("año")            
                estado = form.cleaned_data.get("Estado")
                
                # Usar updatekey en lugar de key para actualizar el objeto en Firebase
                updateitem = dbconn.child(updatekey)
                updateitem.update({
                    "Nombre": nombre,
                    "año": año,
                    "Estado": estado
                })
            return redirect('task')
    return redirect('signin')
def archivarclase(request, Id):
    if 'role' in request.session and request.session['role'] == 'administrativo':
        table = "Cursos"
        dbconn = connectDB(table) 
        tblCursos = dbconn.get()
        # Buscar el curso por el ID generado por Firebase (la clave del documento)
        for key, value in tblCursos.items():
            if key == Id:  # Comparar el ID de Firebase (la clave) directamente con 'Id'
                updateitem = dbconn.child(key)
                # Actualizar el estado del curso a 'Inactivo'
                updateitem.update({
                    "Estado": "Inactivo"
                })
                break

        return redirect('../../Cursos/')  # Redirige a la página que muestra las clases
    return redirect('signin')
def restaurarclase(request, Id):
    if 'role' in request.session and request.session['role'] == 'administrativo':
        table = "Cursos"
        dbconn = connectDB(table) 
        tblCursos = dbconn.get()

        # Buscar el curso por el ID generado por Firebase (la clave del documento)
        for key, value in tblCursos.items():
            if key == Id:  # Comparar el ID de Firebase (la clave) directamente con 'Id'
                updateitem = dbconn.child(key)
                # Actualizar el estado del curso a 'Activo'
                updateitem.update({
                    "Estado": "Activo"
                })
                break

        return redirect('../../Cursos/')  # Redirige a la página que muestra las clases
    return redirect('signin')
def Administrativos_permiso(request):
    if 'role' in request.session and request.session['role'] == 'administrativo':
        table = "Administrativos"
        dbconn = connectDB(table)
        data = dbconn.get()  # Obtener todos los administrativos de la tabla
        Administrativos = []
        busqueda = request.GET.get('busqueda', '')  # Obtener término de búsqueda

        if data:
            for key, value in data.items():
                if isinstance(value, dict):  # Verificar que el valor sea un diccionario
                    Nombre = value.get("Nombre")
                    genero = value.get("genero")
                    Telefono = value.get("Telefono")
                    Gmail = value.get("Gmail")
                    Direccion = value.get("Direccion")
                    Estado = value.get("Estado")

                    if (not busqueda or busqueda.lower() in Nombre.lower()):  # Solo filtrar por búsqueda
                        Administrativo = {
                            "Id": key,  # Usamos el ID generado por Firebase
                            "Nombre": Nombre,
                            "genero": genero,
                            "Telefono": Telefono,
                            "Gmail": Gmail,
                            "Direccion": Direccion,
                            "Estado": Estado,
                        }
                        Administrativos.append(Administrativo)
        
        # Depurar: imprimir los administrativos
        print("Administrativos:", Administrativos)

        return render(request, 'Administrativos_permiso.html', {
            "Administrativos": Administrativos,  # Pasar todos los administrativos al template
            "busqueda": busqueda,
        })
    return redirect('signin')
def aceptar_administrativo(request, Id):
    dbconn = connectDB('Administrativos')  # Conecta a la tabla 'Administrativos'
    administrativo_ref = dbconn.child(Id)
    administrativo = administrativo_ref.get()

    if administrativo:
        # Cambiar el estado a 'Activo'
        administrativo_ref.update({'Estado': 'Activo'})
        return redirect('Administrativos_permiso')  # Redirecciona a la lista de administrativos
    else:
        return HttpResponse("Administrativo no encontrado", status=404)
def eliminar_administrativo(request, Id):
    dbconn = connectDB('Administrativos')  # Conecta a la tabla 'Administrativos'
    administrativo_ref = dbconn.child(Id)
    administrativo = administrativo_ref.get()

    if administrativo:
        # Elimina el administrativo de Firebase
        administrativo_ref.delete()
        return redirect('Administrativos_permiso')  # Redirecciona a la lista de administrativos
    else:
        return HttpResponse("Administrativo no encontrado", status=404)
def Datos_Estadisticos(request, curso_id, estudiante_id):
    if 'role' in request.session and request.session['role'] == 'administrativo':
        dbconn = connectDB("Cursos")

        estudiante_ref = dbconn.child(curso_id).child('Estudiantes').child(estudiante_id).get()
        if not estudiante_ref:
            return redirect('ver_estudiantes', id=curso_id)

        nombre_estudiante = estudiante_ref.get('nombre', 'Nombre no encontrado')
        comportamientos = estudiante_ref.get('Comportamientos', {})

        probabilidades = estudiante_ref.get('Probabilidades', {})
        prob_1_año = probabilidades.get('Prob1Año', 0)
        prob_3_años = probabilidades.get('Prob3Año', 0)
        prob_5_años = probabilidades.get('Prob5Año', 0)

        # Función para generar gráficos de probabilidad (sin dona)
        def generar_grafico_probabilidad(valor):
            fig, ax = plt.subplots()
            ax.pie(
                [valor, 100 - valor],
                labels=[f'{valor}%', ''],
                colors=['#dcbadb', '#f2f2f2'],
                startangle=90,
                wedgeprops={'edgecolor': 'white'},
                radius=1.2
            )
            ax.text(0, 0, f'{valor}%', ha='center', va='center', fontsize=24, fontweight='bold', color='#333333')
            ax.axis('equal')
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            string = base64.b64encode(buf.read())
            plt.close(fig)
            return urllib.parse.quote(string)

        # Función para generar gráficos de comportamiento en forma de dona
        def generar_grafico_dona(valor):
            fig, ax = plt.subplots()
            ax.pie(
                [valor, 100 - valor],
                labels=[f'{valor}%', ''],
                colors=['#dcbadb', '#f2f2f2'],
                startangle=90,
                wedgeprops={'edgecolor': 'white'},
                radius=1.2
            )
            # Crear el círculo blanco central para el efecto de dona
            centre_circle = plt.Circle((0, 0), 0.70, fc='white')
            fig.gca().add_artist(centre_circle)

            ax.text(0, 0, f'{valor}%', ha='center', va='center', fontsize=24, fontweight='bold', color='#572664')
            ax.axis('equal')
            buf = io.BytesIO()
            plt.savefig(buf, format='png', bbox_inches='tight')
            buf.seek(0)
            string = base64.b64encode(buf.read())
            plt.close(fig)
            return urllib.parse.quote(string)

        # Generar gráficos de probabilidad (sin dona)
        grafico_dona_1_año = generar_grafico_probabilidad(prob_1_año)
        grafico_dona_3_años = generar_grafico_probabilidad(prob_3_años)
        grafico_dona_5_años = generar_grafico_probabilidad(prob_5_años)

        # Generar gráficos de comportamiento (en forma de dona)
        graficos = {}
        for comportamiento, valor in comportamientos.items():
            graficos[comportamiento] = generar_grafico_dona(valor)


        # Función para generar gráficos de barras comparativos
        def generar_grafico_barras(valores, labels, color):
           fig, ax = plt.subplots()
           ax.bar(labels, valores, color=color)
           ax.set_ylim(0, 100)
           for i, v in enumerate(valores):
              ax.text(i, v + 2, f"{v}%", ha='center', va='bottom', fontweight='bold')
           buf = io.BytesIO()
           plt.savefig(buf, format='png', bbox_inches='tight')
           buf.seek(0)
           string = base64.b64encode(buf.read())
           plt.close(fig)
           return urllib.parse.quote(string)

        # Valores específicos para los gráficos de barras
        impulsividad = comportamientos.get('Impulsividad', 0)
        paranoia = comportamientos.get('Paranoia', 0)
        tlp = comportamientos.get('TLP', 0)
        narcisismo = comportamientos.get('Narcisismo', 0)
        agresividad = comportamientos.get('Agresividad', 0)

# Generar los gráficos de barras con los valores correspondientes
        grafico_barras_impulsividad_paranoia = generar_grafico_barras(
          [impulsividad, paranoia], ['Impulsividad', 'Paranoia'], color=['#d6eadf', '#eac4d5']
        )
        grafico_barras_tlp_narcisismo = generar_grafico_barras(
          [tlp, narcisismo], ['TLP', 'Narcisismo'], color=['#d3ab9e', '#eac9c1']
        )
        grafico_barras_agresividad = generar_grafico_barras(
          [agresividad], ['Agresividad'], color=['#ff6666']
        )



        # Renderizar la página con todos los gráficos y datos necesarios
        return render(request, 'Datos_Estadisticos.html', {
    'nombre_estudiante': nombre_estudiante,
    'graficos': graficos,
    'prob_1_año': prob_1_año,
    'prob_3_años': prob_3_años,
    'prob_5_años': prob_5_años,
    'grafico_dona_1_año': grafico_dona_1_año,
    'grafico_dona_3_años': grafico_dona_3_años,
    'grafico_dona_5_años': grafico_dona_5_años,
    'grafico_barras_impulsividad_paranoia': grafico_barras_impulsividad_paranoia,
    'grafico_barras_tlp_narcisismo': grafico_barras_tlp_narcisismo,
    'grafico_barras_agresividad': grafico_barras_agresividad
        })


    return redirect('signin')




