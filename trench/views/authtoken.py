from django.contrib.auth import user_logged_in, user_logged_out

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED
from rest_framework.views import APIView
from trench.backends.provider import get_mfa_handler
from trench.command.authenticate_second_factor import authenticate_second_step_command
from trench.exceptions import MFAMethodDoesNotExistError, MFAValidationError
from trench.responses import ErrorResponse
from trench.serializers import CodeLoginSerializer, TokenSerializer
from trench.utils import get_mfa_model, user_token_generator
from trench.views import MFAFirstStepMixin, MFASecondStepMixin, MFAStepMixin


class MFAAuthTokenView(MFAStepMixin):
    def _successful_authentication_response(self, user) -> Response:
        token, _ = Token.objects.get_or_create(user=user)
        user_logged_in.send(sender=user.__class__, request=self.request, user=user)
        return Response(data=TokenSerializer(token).data)


class MFAFirstStepAuthTokenView(MFAAuthTokenView, MFAFirstStepMixin):
    pass


class MFASecondStepAuthTokenView(MFAAuthTokenView, MFASecondStepMixin):
    pass


class MFALogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    @staticmethod
    def post(request: Request) -> Response:
        Token.objects.filter(user=request.user).delete()
        user_logged_out.send(
            sender=request.user.__class__, request=request, user=request.user
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class MFALoginViewSetMixin(MFAAuthTokenView):
    """
    Mixin for usage with DRF ViewSet classes
    """
    def first_step_response(self, user):
        try:
            mfa_model = get_mfa_model()
            mfa_method = mfa_model.objects.get_primary_active(user_id=user.id)
            get_mfa_handler(mfa_method=mfa_method).dispatch_message()
            return Response(
                data={
                    "ephemeral_token": user_token_generator.make_token(user),
                    "method": mfa_method.name,
                }
            )
        except MFAMethodDoesNotExistError:
            return self._successful_authentication_response(user=user)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.first_step_response(serializer.user)

    @action(detail=False, methods=["POST"], permission_classes=[])
    def code(self, request):
        serializer = CodeLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = authenticate_second_step_command(
                code=serializer.validated_data["code"],
                ephemeral_token=serializer.validated_data["ephemeral_token"],
            )
            return self._successful_authentication_response(user=user)
        except MFAValidationError as cause:
            return ErrorResponse(error=cause, status=HTTP_401_UNAUTHORIZED)
