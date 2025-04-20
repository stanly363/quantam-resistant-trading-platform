import time
from decimal import Decimal
from unittest.mock import patch, MagicMock

import pandas as pd
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from bank.models import (
    Profile, Portfolio, Stock, Holding,
    PQServerKey, InvestmentTransaction, AuditLog, Message
)
from bank.crypto_utils import generate_new_key

@override_settings(SECURE_SSL_REDIRECT=False)
class AdminViewsTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        # Create an admin user (signals will set role to admin for superusers)
        self.admin_user = User.objects.create_superuser('admin', 'admin@example.com', 'pass')
        # Create an advisor user and set role to advisor
        self.advisor_user = User.objects.create_user('advisor', 'advisor@example.com', 'pass')
        self.advisor_user.profile.role = 'advisor'
        self.advisor_user.profile.save()
        # Create a client user and assign the advisor
        self.client_user = User.objects.create_user('client', 'client@example.com', 'pass')
        self.client_user.profile.advisor = self.advisor_user
        self.client_user.profile.save()
        # Create a sample stock
        self.stock = Stock.objects.create(
            ticker='AAPL',
            company_name='Apple Inc.',
            last_price=Decimal('150.00')
        )
    def test_admin_create_user_view(self):
        self.client.login(username='admin', password='pass')
        url = reverse('admin_create_user')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        valid_post_data = {
            'username': 'newclient',
            'email': 'newclient@example.com',
            'password1': 'StrongPass123!',
            'password2': 'StrongPass123!',
            'role': 'client',
            'advisor': self.advisor_user.id,
        }
        response = self.client.post(url, valid_post_data, follow=True)
        new_user = User.objects.filter(username='newclient').first()
        self.assertIsNotNone(new_user, "New user should be created for valid data.")
        self.assertEqual(new_user.profile.role, 'client')
        self.assertEqual(new_user.profile.advisor, self.advisor_user)
        invalid_post_data = {
            'username': 'failclient',
            'email': 'fail@example.com',
            'password1': 'Short',
            'password2': 'Short',
            'role': 'client',
            'advisor': self.advisor_user.id,
        }
        response = self.client.post(url, invalid_post_data, follow=True)
        content = response.content.decode().lower()
        self.assertIn("too short", content,
                      "Expected error message for short password not found.")
        self.client.logout()
        self.client.login(username='advisor', password='pass')
        response = self.client.get(url, follow=True)
        content = response.content.decode().lower()
        self.assertIn("access denied", content,
                      "Advisor should see access-denied message when accessing admin create user view.")

    def test_admin_user_detail_view(self):
        self.client.login(username='admin', password='pass')
        url = reverse('admin_user_detail', args=[self.client_user.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.client_user.username)
        
        self.client.logout()
        self.client.login(username='advisor', password='pass')
        response = self.client.get(url, follow=True)
        content = response.content.decode().lower()
        self.assertIn("access denied", content,
                      "Advisor should see access-denied message when accessing admin user detail view.")

    def test_admin_user_delete_view(self):
        self.client.login(username='admin', password='pass')
        user_count_before = User.objects.count()
        url = reverse('admin_user_delete', args=[self.client_user.id])
        # Check delete confirmation page contains expected text.
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("delete", response.content.decode().lower())
        # Perform deletion and verify state change.
        response = self.client.post(url, follow=True)
        user_count_after = User.objects.count()
        self.assertEqual(user_count_after, user_count_before - 1,
                         "User count should decrease by one after deletion.")

@override_settings(SECURE_SSL_REDIRECT=False)
class AdvisorViewsTestCase(TestCase):
    def setUp(self):
        from bank import crypto_utils
        crypto_utils._server_keys_cache = None
        self.client = Client()
        # Create an active encryption key so that transactions succeed.
        self.pq_key = generate_new_key()
        # Create advisor user with role 'advisor'
        self.advisor_user = User.objects.create_user('advisor', 'advisor@example.com', 'pass')
        self.advisor_user.profile.role = 'advisor'
        self.advisor_user.profile.save()
        # Create a client user and assign the advisor; set balance to 10000.
        self.client_user = User.objects.create_user('client', 'client@example.com', 'pass')
        self.client_user.profile.advisor = self.advisor_user
        self.client_user.profile.balance = Decimal('10000')
        self.client_user.profile.save()
        # Create a sample stock
        self.stock = Stock.objects.create(
            ticker='AAPL',
            company_name='Apple Inc.',
            last_price=Decimal('150.00')
        )

    def test_advisor_view_access(self):
        self.client.login(username='advisor', password='pass')
        url = reverse('advisor')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("advisor", response.content.decode().lower())
        self.client.logout()
        self.client.login(username='client', password='pass')
        response = self.client.get(url, follow=True)
        self.assertIn("portfolio", response.content.decode().lower(),
                      "Client should be redirected to portfolio when accessing advisor view.")

    @patch('bank.views.yf.Ticker')
    def test_advisor_transaction_buy_valid(self, mock_ticker):
        # Patch yfinance.Ticker to return a fake history DataFrame with Close=150.00.
        fake_df = pd.DataFrame({'Close': [150.00]})
        mock_instance = MagicMock()
        mock_instance.history.return_value = fake_df
        mock_ticker.return_value = mock_instance

        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_transaction')
        # Ensure client has sufficient funds.
        self.client_user.profile.balance = Decimal('10000')
        self.client_user.profile.save()
        post_data = {
            'client': self.client_user.id,
            'ticker': 'AAPL',
            'shares': '10',
            'action': 'buy',
        }
        response = self.client.post(url, post_data, follow=True)
        # Verify that a holding was created.
        holding = Holding.objects.filter(portfolio=self.client_user.portfolio, stock=self.stock).first()
        self.assertIsNotNone(holding, "Holding should be created for a valid buy transaction.")
        self.assertEqual(holding.shares, Decimal('10'))
        # Verify that the client's balance decreased correctly (10 * 150 = 1500).
        expected_balance = Decimal('10000') - (Decimal('10') * Decimal('150.00'))
        self.client_user.profile.refresh_from_db()
        self.assertEqual(self.client_user.profile.balance, expected_balance)
        # Verify that an InvestmentTransaction record was created.
        tx = InvestmentTransaction.objects.filter(portfolio=self.client_user.portfolio).first()
        self.assertIsNotNone(tx)

    @patch('bank.views.yf.Ticker')
    def test_advisor_transaction_buy_insufficient_funds(self, mock_ticker):
        fake_df = pd.DataFrame({'Close': [150.00]})
        mock_instance = MagicMock()
        mock_instance.history.return_value = fake_df
        mock_ticker.return_value = mock_instance

        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_transaction')
        # Set insufficient funds.
        self.client_user.profile.balance = Decimal('100')
        self.client_user.profile.save()
        post_data = {
            'client': self.client_user.id,
            'ticker': 'AAPL',
            'shares': '10',
            'action': 'buy',
        }
        response = self.client.post(url, post_data, follow=True)
        # Verify that no holding was created and balance remains unchanged.
        holding = Holding.objects.filter(portfolio=self.client_user.portfolio, stock=self.stock).first()
        self.assertIsNone(holding, "No holding should be created when funds are insufficient.")
        self.client_user.profile.refresh_from_db()
        self.assertEqual(self.client_user.profile.balance, Decimal('100'))

    @patch('bank.views.yf.Ticker')
    def test_advisor_transaction_buy_negative_shares(self, mock_ticker):
        fake_df = pd.DataFrame({'Close': [150.00]})
        mock_instance = MagicMock()
        mock_instance.history.return_value = fake_df
        mock_ticker.return_value = mock_instance

        initial_balance = self.client_user.profile.balance
        initial_holdings_count = Holding.objects.filter(
            portfolio=self.client_user.portfolio, stock=self.stock
        ).count()
        initial_tx_count = InvestmentTransaction.objects.filter(
            portfolio=self.client_user.portfolio
        ).count()
        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_transaction')
        post_data = {
            'client': self.client_user.id,
            'ticker': 'AAPL',
            'shares': '-10',  # Negative share input.
            'action': 'buy',
        }
        response = self.client.post(url, post_data, follow=True)
        # Retrieve messages from the response.
        messages_list = list(get_messages(response.wsgi_request))
        error_found = any("must buy at least" in message.message.lower() for message in messages_list)
        self.assertTrue(error_found, "Expected error message for negative share input not found.")
        # Verify that no new holding was created or modified.
        holdings_count = Holding.objects.filter(
            portfolio=self.client_user.portfolio, stock=self.stock
        ).count()
        self.assertEqual(holdings_count, initial_holdings_count,
                         "Holding record should not be created/modified for negative share input.")
        # Verify that no new InvestmentTransaction record was created.
        tx_count = InvestmentTransaction.objects.filter(
            portfolio=self.client_user.portfolio
        ).count()
        self.assertEqual(tx_count, initial_tx_count,
                         "InvestmentTransaction record should not be created for negative share input.")
        # Verify that the client's balance remains unchanged.
        self.client_user.profile.refresh_from_db()
        self.assertEqual(self.client_user.profile.balance, initial_balance,
                         "Client's balance should not change for negative share input.")

    @patch('bank.views.yf.Ticker')
    def test_advisor_transaction_sell_valid(self, mock_ticker):
        fake_df = pd.DataFrame({'Close': [150.00]})
        mock_instance = MagicMock()
        mock_instance.history.return_value = fake_df
        mock_ticker.return_value = mock_instance
        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_transaction')
        # Pre-create a holding with 10 shares.
        Holding.objects.create(
            portfolio=self.client_user.portfolio,
            stock=self.stock,
            shares=Decimal('10')
        )
        self.client_user.profile.balance = Decimal('5000')
        self.client_user.profile.save()
        post_data = {
            'client': self.client_user.id,
            'ticker': 'AAPL',
            'shares': '10',
            'action': 'sell',
        }
        response = self.client.post(url, post_data, follow=True)
        # Verify that the holding is removed.
        holding = Holding.objects.filter(portfolio=self.client_user.portfolio, stock=self.stock).first()
        self.assertIsNone(holding, "Holding should be removed after selling all shares.")
        # Verify that the client's balance increased correctly (10 * 150 = 1500).
        expected_balance = Decimal('5000') + (Decimal('10') * Decimal('150.00'))
        self.client_user.profile.refresh_from_db()
        self.assertEqual(self.client_user.profile.balance, expected_balance)
        tx = InvestmentTransaction.objects.filter(portfolio=self.client_user.portfolio).first()
        self.assertIsNotNone(tx, "InvestmentTransaction record should be created for valid sell transaction.")

    def test_advisor_transaction_sell_insufficient_shares(self):
        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_transaction')
        holding = Holding.objects.create(
            portfolio=self.client_user.portfolio,
            stock=self.stock,
            shares=Decimal('5')
        )
        post_data = {
            'client': self.client_user.id,
            'ticker': 'AAPL',
            'shares': '10',  # Trying to sell more than held.
            'action': 'sell',
        }
        response = self.client.post(url, post_data, follow=True)
        # Verify that the holding remains unchanged.
        holding.refresh_from_db()
        self.assertEqual(holding.shares, Decimal('5'),
                         "Holding should remain unchanged when attempting to sell insufficient shares.")
        self.client_user.profile.refresh_from_db()
        self.assertEqual(self.client_user.profile.balance, Decimal('10000'),
                         "Client's balance should not change when selling insufficient shares.")

    def test_advisor_client_detail_view(self):
        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_client_detail', args=[self.client_user.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.client_user.username, response.content.decode())
        self.client.logout()
        self.client.login(username='client', password='pass')
        response = self.client.get(url, follow=True)
        self.assertIn("portfolio", response.content.decode().lower(),
                      "Client accessing advisor client detail should be redirected to portfolio.")

    @patch('django.template.loader.get_template')
    def test_advisor_message_view_invalid(self, mock_get_template):
        dummy_template = type("DummyTemplate", (), {"render": lambda self, context, request=None: "dummy"})()
        mock_get_template.return_value = dummy_template

        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_message')
        initial_message_count = Message.objects.count()
        post_data = {'recipient': '', 'message': 'Advice'}
        response = self.client.post(url, post_data, follow=True)
        self.assertEqual(Message.objects.count(), initial_message_count,
                         "No message should be created if recipient is missing.")
        post_data = {'recipient': self.client_user.username, 'message': ''}
        response = self.client.post(url, post_data, follow=True)
        self.assertEqual(Message.objects.count(), initial_message_count,
                         "No message should be created if message text is missing.")
        post_data = {'recipient': 'nonexistent', 'message': 'Advice'}
        response = self.client.post(url, post_data, follow=True)
        self.assertEqual(Message.objects.count(), initial_message_count,
                         "No message should be created if recipient does not exist.")

    @patch('django.template.loader.get_template')
    def test_advisor_message_view_valid(self, mock_get_template):
        dummy_template = type("DummyTemplate", (), {"render": lambda self, context, request=None: "dummy"})()
        mock_get_template.return_value = dummy_template

        self.client.login(username='advisor', password='pass')
        url = reverse('advisor_message')
        initial_message_count = Message.objects.count()
        post_data = {'recipient': self.client_user.username, 'message': 'Investment advice'}
        response = self.client.post(url, post_data, follow=True)
        self.assertEqual(Message.objects.count(), initial_message_count + 1,
                         "A valid message should be created when recipient and message text are provided.")
        msg = Message.objects.filter(sender=self.advisor_user, recipient=self.client_user).first()
        self.assertIsNotNone(msg, "Message record should exist for a valid message.")

    def test_non_advisor_access_to_advisor_views(self):
        advisor_url = reverse('advisor')
        self.client.login(username='client', password='pass')
        response = self.client.get(advisor_url, follow=True)
        self.assertIn("portfolio", response.content.decode().lower(),
                      "Client should be redirected to portfolio when accessing advisor view.")
        trans_url = reverse('advisor_transaction')
        response = self.client.get(trans_url, follow=True)
        self.assertIn("portfolio", response.content.decode().lower(),
                      "Client should be redirected to portfolio when accessing advisor transaction view.")
