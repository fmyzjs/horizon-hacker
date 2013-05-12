# vim: tabstop=4 shiftwidth=4 softtabstop=4
from django.forms.util import ErrorList
from django.utils.translation import ugettext as _
from horizon import forms
from horizon.utils import validators
from django.conf import settings
from django.views.decorators.debug import sensitive_variables
import ConfigParser
import commands
"""
Forms used for Horizon's register mechanisms.
"""
class BaseRegForm(forms.SelfHandlingForm):
    def __init__(self, request, *args, **kwargs):
        super(BaseRegForm, self).__init__(request, *args, **kwargs)
class RegForm(BaseRegForm):
    """ Form used for logging in a user.

    Handles authentication with Keystone, choosing a tenant, and fetching
    a scoped token token for that tenant. Redirects to the URL returned
    by :meth:`horizon.get_user_home` if successful.

    Subclass of :class:`~horizon.forms.SelfHandlingForm`.
    """
    
    username = forms.CharField(label=_("User Name"), min_length=5, max_length=30, required=True)
    email = forms.EmailField(label=_("E-mail"))
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
    def __init__(self, *args, **kwargs):
        super(RegForm, self).__init__(*args, **kwargs)
    '''def clean(self):
        password = self.cleaned_data.get('password', '').strip()
        confirm_password = self.cleaned_data.get('confirm_password', '').strip()
        if len(password)<6 or len(password)>18 or password != confirm_password:
            self._errors["password"] = ErrorList([_('Password must be between 8 and 18 characters.')])
            self._errors["confirm_password"] = ErrorList([_('Confirm Password must be same with password.')])
            del self.cleaned_data["confirm_password"]
        return self.cleaned_data'''
    def clean(self):
        '''Check to make sure password fields match.'''
        data = super(forms.Form, self).clean()
        if 'password' in data:
            if data['password'] != data.get('confirm_password', None):
                raise ValidationError(_('Passwords do not match.'))
        return data

    @sensitive_variables('data')
    def handle(self, request, data):
        username = data['username']
        password= data['password']
        tenantname=username
        email = data['email']
        cfg=ConfigParser.ConfigParser()
        cfg.read('/etc/nova/api-paste.ini')
        keystone_cfg=dict(cfg.items('filter:authtoken'))
        try:
            LOG.info('Creating user with name "%s"' % data['name'])
            tenant_cmd="/usr/bin/keystone --os_tenant_name=%s --os_username=%s --os_password=%s --os_auth_url=%s tenant-create --name %s |grep id |awk '{print $4}'" % (keystone_cfg['admin_tenant_name'],keystone_cfg['admin_user'],keystone_cfg['admin_password'],settings.OPENSTACK_KEYSTONE_URL,tenantname)
            tenant_cmd_op=commands.getstatusoutput(tenant_cmd) 
            if(len(tenant_cmd_op[1])==32):
                new_user=user_cmd="/usr/bin/keystone --os_tenant_name=%s --os_username=%s --os_password=%s --os_auth_url=%s user-create --name %s --tenant_id %s --pass %s --email %s |sed -n '6p' | awk '{print $4}'" % (keystone_cfg['admin_tenant_name'],keystone_cfg['admin_user'],keystone_cfg['admin_password'],settings.OPENSTACK_KEYSTONE_URL,username,tenant_cmd_op[1],password,email)
                user_cmd_op=commands.getstatusoutput(user_cmd)
                if(len(user_cmd_op[1])==32):
                    messages.success(request,
                                 _('User "%s" was successfully created.')
                                 % data['name'])
                else:
                    exceptions.handle(request, _('Unable to create user.'))
 
                return new_user
        except:
            exceptions.handle(request, _('Unable to create user.'))

