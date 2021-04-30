from django import forms
from .models import company_details

class CompanydetailForm(forms.ModelForm):
    class Meta:
        model = company_details
        fields = "__all__"

        widget = {
            'country': forms.TextInput(attrs={'class': 'form-control'})
        }