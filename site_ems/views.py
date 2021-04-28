from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.models import User, auth
from django.core.mail import send_mail, BadHeaderError
from django.db.models.query_utils import Q
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.contrib.auth import views as auth_views, get_user_model
from django import forms
from django.views.generic import FormView
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from .models import company_details
from .forms import CompanydetailForm


# Create your views here.
def index(request):
    print("in index ")
    return HttpResponse('Hello, welcome to the index page.')

def about(request):
    return render(request, 'about.html')

def home(request):
    if request.user.is_superuser:
        return render(request, 'adminpage.html')
    else:
        return render(request,'userpage.html')

@csrf_exempt
def login(request):
    if request.method == 'POST':
        unm = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=unm, password=password)

        if user is not None:
            auth.login(request, user)
            if request.user.is_superuser:
                return render(request, 'adminpage.html')
            else:
                return render(request, 'userpage.html')
        else:
            messages.info(request, "Invalid credentials")
            return redirect('login_page')
    else:
        return render(request, 'login_page.html')

def adminpage(request):
    return render(request, 'adminpage.html')

def userpage(request):
    return render(request, 'userpage.html')

def cmp(request):
    if request.method == "POST":
        form = CompanydetailForm(request.POST)
        if form.is_valid():
                form.save()
                print(" form is valid and in try block")
                return redirect('/show')
    else:
        print("in else part")
        form = CompanydetailForm()
    return render(request,'cmp1.html',{'form':form})

def add_company_details(request):
    #recent_id = company_details.objects.all()
#    ls = []
#    for i in recent_id:
#        temp = i.short_nm + i.company_nm + i.street + i.town + i.zip
#        ls.append(temp)
#    print("ls:",ls)
    show(request)
    return render(request,'addcompany.html')

def show(request):
    print("in show")
    cd = company_details.objects.all()
    return render(request, "show.html", {'cd': cd})

def edit(request, id):
    employee = company_details.objects.get(id=id)
    return render(request,'edit.html', {'employee':employee})

def update(request, id):
    form = CompanydetailForm()
    if request.method == 'POST':
        employee = company_details.objects.get(id=id)
        form = CompanydetailForm(request.POST, instance=employee)
        print("in update before loop:", employee, id)
        print(employee.company_nm)
        print(form.is_valid())
        print(form.errors)
        if form.is_valid():
            form.save()
            print("in update inside loop:", employee)
            return redirect("/show")
    return render(request, 'edit.html', {'employee': employee})

def destroy(request, id):
    employee = company_details.objects.get(id=id)
    employee.delete()
    return redirect("/show")

def error_404(request,exception):
    values_for_template = {}
    return render(request, 'page_not_found.html', values_for_template, status=404)

def error_500(request,exception):
    # Dict to pass to template, data could come from DB query
    values_for_template = {}
    return render(request, 'server_error.html', values_for_template, status=500)

def server_error(request):
    # Dict to pass to template, data could come from DB query
    values_for_template = {}
    return render(request,'server_error.html',values_for_template,status=500)

def error_403(request,exception):
    values_for_template = {}
    return render(request, 'permission_denied.html', values_for_template, status=403)

def error_400(request,exception):
    values_for_template = {}
    return render(request, 'bad_request.html', values_for_template, status=400)

def logout(request):
    auth.logout(request)
    return redirect('/')

def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(Q(email=data))
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "Forgot_password/password_reset_email.txt"
                    c = {
                    "email":user.email,
                    'domain':'ecubesolutions.in',
                    'site_name': 'ecubesolutions.in',
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "user": user,
                    'token': default_token_generator.make_token(user),
                    'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_mail(subject, email, 'ecubesolutio99@gmail.com' , [user.email], fail_silently=False)
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')
                    messages.success(request, 'A message with reset password instructions has been sent to your inbox.')
                    return redirect("/")
                    #return redirect ("/password_reset/done/")
            messages.error(request, 'An invalid email has been entered.')
    password_reset_form = PasswordResetForm()
    return render(request= request, template_name="Forgot_password/password_reset.html",
                  context={"password_reset_form": password_reset_form})


class SetPasswordForm(forms.Form):
    error_messages = {
        'password_mismatch': ("The two password fields didn't match."),
        }
    new_password1 = forms.CharField(label=("New password"), required=True,
                                    widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=("New password confirmation"), required=True,
                                    widget=forms.PasswordInput)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

class PasswordResetConfirmView(FormView):
    template_name = "Forgot_password/password_reset_confirm.html"
    success_url = '/admin/'
    form_class = SetPasswordForm

    def form_valid(self, *arg, **kwargs):
        form = super(PasswordResetConfirmView, self).form_valid(*arg, **kwargs)
        uidb64=self.kwargs['uidb64']
        token=self.kwargs['token']
        UserModel = get_user_model()
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = User._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            new_password= form.cleaned_data['new_password2']
            user.set_password(new_password)
            user.save()
            messages.success(self.request, 'Password reset has been successful.')
        else:
            messages.error(self.request, 'Password reset has not been unsuccessful.')
        return form
