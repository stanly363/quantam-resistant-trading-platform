from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

ROLE_CHOICES = [
    ('client', 'Client'),
    ('advisor', 'Financial Advisor'),
    # Admin accounts are typically created separately.
]

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    role = forms.ChoiceField(choices=ROLE_CHOICES)
    advisor = forms.ModelChoiceField(
        queryset=User.objects.none(),
        required=False,
        empty_label="None"
    )
    
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2", "role", "advisor")
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Determine the role from POST data (if available) or initial data.
        role = self.data.get('role') if self.data.get('role') else self.initial.get('role', None)
        if role == 'advisor':
            # If registering as an advisor, force the advisor field to be empty.
            self.fields['advisor'].queryset = User.objects.none()
            # Disable the field so it cannot be modified.
            self.fields['advisor'].widget.attrs['disabled'] = True
        else:
            # For clients, set the advisor queryset to available advisors.
            self.fields['advisor'].queryset = User.objects.filter(profile__role='advisor')
    
    def clean_advisor(self):
        # Ensure that if the role is advisor, the advisor field always returns None.
        role = self.cleaned_data.get('role')
        if role == 'advisor':
            return None
        return self.cleaned_data.get('advisor')

class TransactionForm(forms.Form):
    recipient = forms.CharField(max_length=150)
    amount = forms.DecimalField(max_digits=12, decimal_places=2)

class InvestForm(forms.Form):
    shares = forms.DecimalField(max_digits=12, decimal_places=2, min_value=0.01)

class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']