# vim: tabstop=4 shiftwidth=4 softtabstop=4
from django.forms import ValidationError
from django.utils.translation import force_unicode, ugettext_lazy as _
from django.views.decorators.debug import sensitive_variables

from horizon import exceptions
from horizon import forms
from horizon import messages
from horizon.utils import validators

from openstack_dashboard import api
#LOG = logging.getLogger(__name__)
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
    tenant_id = '1f71e9b36cd444568d51fc6815062f14'
    role_id = '7570f5898850496f958de842f85c6f57'

    @sensitive_variables('data')
    def handle(self, request, data):
        try:
            LOG.info('Creating user with name "%s"' % data['name'])
            username = data['name'],
            email = data['email'],
            password = data['password'],
            tenant_id = data['tenant_id'],
            cfg=ConfigParser.ConfigParser()
            cfg.read('/etc/nova/api-paste.ini')
            keystone_cfg=dict(cfg.items('filter:authtoken'))
            #tenant_cmd="/usr/bin/keystone --os_tenant_name=%s --os_username=%s --os_password=%s --os_auth_url=%s tenant-create --name %s |grep id |awk '{print $4}'" % (keystone_cfg['admin_tenant_name'],keystone_cfg['admin_user'],keystone_cfg['admin_password'],settings.OPENSTACK_KEYSTONE_URL,tenantname)
            #tenant_cmd_op=commands.getstatusoutput(tenant_cmd)
            user_cmd="/usr/bin/keystone --os_tenant_name=%s --os_username=%s --os_password=%s --os_auth_url=%s user-create --name %s --tenant_id %s --pass %s --email %s |sed -n '6p' | awk '{print $4}'" % (keystone_cfg['admin_tenant_name'],keystone_cfg['admin_user'],keystone_cfg['admin_password'],settings.OPENSTACK_KEYSTONE_URL,username,tenant_id,password,email)
            user_cmd_op=commands.getstatusoutput(user_cmd)
            if(len(user_cmd_op[1])==32):
                return shortcuts.render(request, 'register/index.html', {'username':username,'email':email})

            return new_user
        except:
            return shortcuts.render(request, 'register/index.html', {'form': rf,'error':er})
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

