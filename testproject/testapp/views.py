from rest_framework import viewsets
from rest_framework.permissions import AllowAny

from trench.views.authtoken import MFAAuthTokenViewSetMixin

from .serializers import LoginSerializer


class LoginMfaViewSet(viewsets.GenericViewSet, MFAAuthTokenViewSetMixin):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
