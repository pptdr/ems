from django.db import models
from django.core.validators import RegexValidator

# Create your models here.
class company_details(models.Model):
    short_nm = models.CharField(max_length=10)
    company_nm= models.CharField(max_length=55)
    street = models.CharField(max_length=255)
    town = models.CharField(max_length=30)
    zip_code = models.CharField(max_length=6, validators=[RegexValidator(r'^\d{1,10}$')])
    country = models.CharField(max_length=30)
    internet_address = models.CharField(max_length=50)
    contact_person = models.CharField(max_length=100)
    telephone_number = models.CharField(max_length=10, validators=[RegexValidator(r'^\d{1,10}$')])
    email = models.EmailField()
    fax_no = models.CharField(max_length=10, validators=[RegexValidator(r'^\d{1,10}$')])
    tax_no1 = models.CharField(max_length=10, validators=[RegexValidator(r'^\d{1,10}$')])
    tax_no2 = models.CharField(max_length=10, validators=[RegexValidator(r'^\d{1,10}$')])

    #class Meta:
    #    db_table = "company_details"