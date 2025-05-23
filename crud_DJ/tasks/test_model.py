import numpy as np
import tensorflow as tf
import joblib

# Cargar el modelo
model_path = "crud_DJ\\tasks\\static\\IA\\personality_disorder_prediction_model.h5" 
scaler_path = "crud_DJ\\tasks\\static\\IA\\scaler_trastornos_personalidad.save" 

# Carga el modelo usando tf.keras
model = tf.keras.models.load_model(model_path)

# Carga el scaler
scaler = joblib.load(scaler_path)

# Verifica que el modelo y el scaler se hayan cargado correctamente
print("Modelo cargado:", model)
print("Scaler cargado:", scaler)

# Genera algunos datos de prueba
datos_prueba = np.array([[50, 72, 83, 65, 15]])   # Reemplaza con tus datos reales
datos_prueba_escalados = scaler.transform(datos_prueba)

# Realiza la predicción
predicciones = model.predict(datos_prueba_escalados)
print("Predicciones:", predicciones)
