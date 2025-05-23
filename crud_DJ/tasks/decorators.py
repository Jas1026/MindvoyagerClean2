from django.shortcuts import redirect
from django.contrib.auth import logout
from functools import wraps

def role_required(required_role):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Verificar si el usuario tiene un rol en la sesión
            if 'role' in request.session:
                # Si el rol no coincide con el requerido, cerrar sesión
                if request.session['role'] != required_role:
                    logout(request)  # Cerrar la sesión del usuario
                    return redirect('signin')  # Redirigir al login
                return view_func(request, *args, **kwargs)
            # Si no hay rol en la sesión, cerrar sesión y redirigir al login
            logout(request)
            return redirect('signin')
        return _wrapped_view
    return decorator
