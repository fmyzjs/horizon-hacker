# vim: tabstop=4 shiftwidth=4 softtabstop=4
from django.forms.util import ErrorList
from django.utils.translation import ugettext as _
from horizon import exceptions
from horizon import forms
from horizon import messages
from horizon.utils import validators

from openstack_dashboard import api

"""
Forms used for Horizon's register mechanisms.
"""

class RegForm(forms.SelfHandlingForm):
    def __init__(self, request, *args, **kwargs):
        super(RegForm, self).__init__(request, *args, **kwargs)
    """ Form used for logging in a user.

    Handles authentication with Keystone, choosing a tenant, and fetching
    a scoped token token for that tenant. Redirects to the URL returned
    by :meth:`horizon.get_user_home` if successful.

    Subclass of :class:`~horizon.forms.SelfHandlingForm`.
    """
    def clean(self):
        '''Check to make sure password fields match.'''
        data = super(forms.Form, self).clean()
        if 'password' in data:
            if data['password'] != data.get('confirm_password', None):
                raise ValidationError(_('Passwords do not match.'))
        return data

class RegUserForm(RegForm):       
    name = forms.CharField(label=_("User Name"), min_length=5, max_length=30, required=True)
    email = forms.EmailField(label=_("Email"))
    password = forms.RegexField(
            label=_("Password"),
            widget=forms.PasswordInput(render_value=False),
            regex=validators.password_validator(),
            error_messages={'invalid': validators.password_validator_msg()})
    #error_messages={'required': _('Confirm Password must be same with password.')}
    confirm_password = forms.CharField(
            label=_("Confirm Password"),
            required=False,
            widget=forms.PasswordInput(render_value=False))
    tenant_id = ''
    role_id = ''

        @sensitive_variables('data')
    def handle(self, request, data):
        try:
            LOG.info('Creating user with name "%s"' % data['name'])
            new_user = api.keystone.user_create(request,
                                                data['name'],
                                                data['email'],
                                                data['password'],
                                                data['tenant_id'],
                                                True)
            messages.success(request,
                             _('User "%s" was successfully created.')
                             % data['name'])
            if data['role_id']:
                try:
                    api.keystone.add_tenant_user_role(request,
                                             data['tenant_id'],
                                             new_user.id,
                                             data['role_id'])
                except:
                    exceptions.handle(request,
                                      _('Unable to add user'
                                        'to primary project.'))
            return new_user
        except:
            exceptions.handle(request, _('Unable to create user.'))



   ''' def __init__(self, *args, **kwargs):
        super(RegForm, self).__init__(*args, **kwargs)
    def clean(self):
        password = self.cleaned_data.get('password', '').strip()
        confirm_password = self.cleaned_data.get('confirm_password', '').strip()
        if len(password)<6 or len(password)>18 or password != confirm_password:
            self._errors["password"] = ErrorList([_('Password must be between 8 and 18 characters.')])
            self._errors["confirm_password"] = ErrorList([_('Confirm Password must be same with password.')])
            del self.cleaned_data["confirm_password"]
        return self.cleaned_data'''

