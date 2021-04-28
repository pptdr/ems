from django import forms
from .models import company_details

class CompanydetailForm(forms.ModelForm):
    class Meta:
        model = company_details
        fields = "__all__"