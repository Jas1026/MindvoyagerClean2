from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class task(models.Model):
    Nombre = models.CharField(max_length= 200)
    año = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    estado = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class Cursos(models.Model):
    Nombre = models.CharField(max_length= 200)
    año = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    estado = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

class Estudiante(models.Model):
    Nombre = models.CharField(max_length= 200)
    Edad =  models.IntegerField()
    ProgresoEnElJuego = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)    
    estado = models.BooleanField(default=False)    