# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2018-11-23 09:25
from __future__ import unicode_literals

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("testapp", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="yubikey_id",
            field=models.CharField(
                blank=True,
                max_length=12,
                validators=[django.core.validators.MinLengthValidator(12)],
            ),
        ),
    ]
