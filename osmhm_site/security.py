from sqlalchemy.orm import (
    scoped_session,
    sessionmaker,
)
from zope.sqlalchemy import register

from osmhm_site.models import DBSession, Base, User

from pyramid.security import (
    Allow,
    Everyone,
    Deny,
)

class RootFactory(object):
    __acl__ = [
        (Allow, Everyone, 'view'),
        (Allow, 'group:member', 'watch_user_or_object'),
        (Allow, 'group:member', 'edit_user_or_object'),
        (Allow, 'group:admin', 'watch_user_or_object'),
        (Allow, 'group:admin', 'edit_user_or_object'),
        (Allow, 'group:owner', 'watch_user_or_object'),
        (Allow, 'group:owner', 'edit_user_or_object'),
        (Allow, 'group:owner', 'super_admin'),
    ]
    def __init__(self, request):
        pass

def group_membership(username, request):
    user = DBSession.query(User).get(username)
    perms = []
    if user:
        if user.is_owner:
            perms += ['group:owner']
        if user.is_admin:
            perms += ['group:admin']
        if user.is_member:
            perms += ['group:member']
    return perms
