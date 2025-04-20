from django.apps import AppConfig
from django.core.management import call_command

class BankConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'bank'

    def ready(self):
        import bank.signals
        # Call the management command to import stocks.
        # Note: Be cautious—this may run more than once in production (e.g. with multiple processes).
        try:
            call_command('import_stocks')
        except Exception as e:
            # You might log the error instead of passing
            pass

