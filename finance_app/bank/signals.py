from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile, Portfolio

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        # If user is created, set role to 'admin' if superuser; otherwise default to 'client'
        role = 'admin' if instance.is_superuser else 'client'
        Profile.objects.create(user=instance, role=role)
        Portfolio.objects.create(user=instance)  # Create portfolio for investments
    else:
        try:
            profile = instance.profile
        except Profile.DoesNotExist:
            profile = Profile.objects.create(user=instance)
        if instance.is_superuser:
            profile.role = 'admin'
        profile.save()
