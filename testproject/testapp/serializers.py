from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers
from rest_framework.authtoken.models import Token
from testapp.models import User


class ExtendedUserSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(allow_blank=True)

    class Meta:
        model = get_user_model()
        fields = ("id", "email", "username", "phone_number")
        read_only_fields = (User.USERNAME_FIELD,)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate_username(self, username):
        try:
            self.user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError(_("Username does not exist."))
        return username

    def validate(self, data):
        if not self.user.check_password(data["password"]):
            raise serializers.ValidationError({"password": _("Incorrect password.")})
        return data

    def create(self, validated_data):
        return Token.objects.get_or_create(user=self.user)[0]
