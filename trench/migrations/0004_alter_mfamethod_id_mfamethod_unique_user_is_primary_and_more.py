# Generated by Django 4.1.3 on 2022-11-16 12:58

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("trench", "0003_auto_20190213_2330"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="mfamethod",
            constraint=models.UniqueConstraint(
                condition=models.Q(("is_primary", True)),
                fields=("user",),
                name="unique_user_is_primary",
            ),
        ),
        migrations.AddConstraint(
            model_name="mfamethod",
            constraint=models.CheckConstraint(
                check=models.Q(
                    models.Q(("is_primary", True), ("is_active", True)),
                    models.Q(("is_primary", False)),
                    _connector="OR",
                ),
                name="primary_is_active",
            ),
        ),
    ]
