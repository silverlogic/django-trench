from rest_framework.routers import DefaultRouter
from .views import LoginMfaViewSet


router = DefaultRouter(trailing_slash=False)


# Login / Register
router.register(r"login", LoginMfaViewSet, basename="login")
