from functools import wraps


from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test
from django.db import connection
from django.http import HttpResponseForbidden
from django.utils.translation import ugettext as _


from autoreg.whois.db import suffixadd, check_handle_domain_auth
from .models import check_is_admin


def login_active_required(function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None):
    """
    Decorator for views that checks that the user is logged in AND the account
    is active, redirecting to the log-in page if necessary.

    This allows for immediate account blocking.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and u.is_active,
        login_url=login_url,
        redirect_field_name=redirect_field_name
    )
    if function:
        return actual_decorator(function)
    return actual_decorator


def check_handle_fqdn_perms(function):
    """
    Decorator for views that checks that the user is admin or
    has rights on domain designated by argument 'fqdn'.

    Note: fqdn should be present and named (keyword argument)
    by the caller, else it will not be checked.
    """

    def decorator(view_func):
      @wraps(view_func)
      def _wrapped_view(request, *args, **kwargs):
          handle = suffixadd(request.user.username)
          fqdn = kwargs.get('fqdn', None)
          if fqdn is not None \
             and not check_is_admin(request.user.username) \
             and not check_handle_domain_auth(connection.cursor(),
                                              suffixadd(request.user.username),
                                              fqdn):
               return HttpResponseForbidden(_("Unauthorized"))
          return view_func(request, *args, **kwargs)
      return _wrapped_view
    if function:
      return decorator(function)
    return decorator
