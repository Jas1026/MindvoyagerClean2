from django import forms

class NivelForm(forms.Form):
    Id= forms.IntegerField()
    Nombre= forms.CharField(max_length=100)
    Estado= forms.CharField(max_length=100)

class CursoForm(forms.Form):
    Nombre= forms.CharField(max_length=100)
    año= forms.CharField(max_length=10)
    Estado= forms.CharField(max_length=100)
