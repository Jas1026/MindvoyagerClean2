"""
URL configuration for crud_DJ project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from tasks import views
from django.views.generic import RedirectView
urlpatterns = [
    path('admin/', admin.site.urls),
    path('home/', views.home, name= "home"),
    path('', RedirectView.as_view(url='/home/', permanent=False)), 
    path('verify_ci/<slug:estudiante_id>/<slug:ci_digits>/', views.verify_ci, name='verify_ci'),
    path('signup/', views.signup, name='signup'),
    path('register_admin/', views.register_admin, name='register_admin'),
    path('get_estudiante_info/<slug:estudiante_id>/', views.get_estudiante_info, name='get_estudiante_info'),
    path('task/', views.task, name= 'task'),
    path('logout/', views.signout, name= 'logout'),
    path('signin/', views.signin, name= 'signin'),
    path('miPerfil/', views.miPerfil, name= 'miPerfil'),
    path('update_profile/', views.update_profile, name='update_profile'),
    path('Detall_Niveles/', views.Detall_Niveles, name='Detall_Niveles'),
    path('Cursos/', views.ListarClase, name= 'cursos'),
    path('Estudiantes/<slug:id>/', views.ver_estudiantes, name='ver_estudiantes'),
    path('cursos/<slug:curso_id>/estudiantes/<slug:estudiante_id>/archivar/', views.archivar_estudiante, name='archivar_estudiante'),
    path('cursos/<slug:curso_id>/estudiantes/<slug:estudiante_id>/restaurar/', views.restaurar_estudiante, name='restaurar_estudiante'),
    path('cargar_estudiante/<slug:curso_slug>/<slug:estudiante_slug>/', views.cargar_datos_estudiante, name='cargar_datos_estudiante'),
     path('editar_estudiante/<slug:curso_id>/<slug:estudiante_id>/', views.editar_estudiante, name='editar_estudiante'),
    path('Resumen/', views.Resumen, name= 'Resumen'),
    path('CasosCriticos/', views.CasosCriticos, name= 'CasosCriticos'),
    path('Niveles/', views.Niveles_juego, name= 'Niveles'),
    path('Add_nivel/', views.addNivel, name='Add_nivel'),
    path('Add_clase/', views.addclase, name='Add_clase'),
    path('cursos/<slug:id>/agregar-estudiante/', views.agregar_estudiante, name='agregar_estudiante'),
    path('updatecar/<int:Id>/', views.updatecar, name='updatecar'),
    path('updateclase/<slug:Id>/', views.updateclase, name='updateclase'),
    path('archivarclase/<slug:Id>/', views.archivarclase, name='archivarclase'),
    path('restaurarclase/<slug:Id>/', views.restaurarclase, name='restaurarclase'),
    path('aceptar/<slug:Id>/', views.aceptar_administrativo, name='aceptar_administrativo'),
    path('eliminar/<slug:Id>/', views.eliminar_administrativo, name='eliminar_administrativo'),
    path('Administrativos_permiso/', views.Administrativos_permiso, name = 'Administrativos_permiso'),
    path('Datos_Estadisticos/<slug:curso_id>/<slug:estudiante_id>/', views.Datos_Estadisticos, name='Datos_Estadisticos')

]
