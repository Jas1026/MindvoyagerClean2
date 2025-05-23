import firebase_admin
from firebase_admin import credentials
from firebase_admin import db

# Ruta correcta al archivo de credenciales
cred = credentials.Certificate("crud_DJ/mindvoyager-67287-firebase-adminsdk-n96en-ece0d7cd30.json")

# Inicializa la aplicación de Firebase con la URL de la base de datos
firebase_admin.initialize_app(cred, {
    "databaseURL": "https://mindvoyager-67287-default-rtdb.firebaseio.com/"
})

# Referencia a la base de datos en la rama "Cursos"
dbref = db.reference("Cursos")

# Inserta un curso con tres estudiantes
nuevo_curso_ref = dbref.push({
    "Id": 2,
    "Nombre": "3ro secundaria",
    "año": "2022",
    "Estado": "Activo"
})

# Referencia a la subcolección "Estudiantes" dentro del nuevo curso
estudiantes_ref = nuevo_curso_ref.child("Estudiantes")

# Añade tres estudiantes a la subcolección "Estudiantes"
estudiantes_ref.push({"Id": 1, "nombre": "karen", "edad": 15, "genero": "Femenino", "estado": "activo"})
# Imprime los datos del curso y sus estudiantes de la base de datos
print(dbref.get())
