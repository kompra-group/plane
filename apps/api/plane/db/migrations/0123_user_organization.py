from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("db", "0122_alter_draftissue_assignees_alter_issue_assignees_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="organization",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
