from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import (
    Profile, Portfolio, Stock, Holding,
    InvestmentTransaction, AuditLog, PQServerKey,
)
from django.db import transaction  # Ensures atomic transactions

from . import crypto_utils
from .crypto_utils import get_server_keys, generate_new_key
import time, base64, json
import yfinance as yf
from django.utils import timezone
from .forms import RegistrationForm, InvestForm, TransactionForm
from decimal import Decimal
from django.http import JsonResponse
from .models import PortfolioHistory
from django.db.models import Q
from .models import Message
from django.db.models import Sum
from .forms import UserUpdateForm
from .crypto_utils import encrypt_field,decrypt_field, reset_server_keys_cache
@login_required
def profile_update_view(request):
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been successfully updated.")
            return redirect('profile_update')
        else:
            # Iterate over form errors and add detailed messages
            for field, errors in form.errors.items():
                # Get the field label from the form; if field is '__all__', use a generic label.
                field_label = form.fields[field].label if field in form.fields else "Error"
                for error in errors:
                    messages.error(request, f"{field_label}: {error}")
    else:
        form = UserUpdateForm(instance=request.user)
    return render(request, 'profile_update.html', {'form': form})

@login_required
def create_chat_view(request):
    """
    Displays a form where the current user can enter a username to start a chat.
    Upon submission, verifies that the user exists and redirects to the chat detail view.
    """
    if request.method == 'POST':
        username = request.POST.get("username").strip()
        if username == request.user.username:
            messages.error(request, "You cannot chat with yourself.")
            return redirect('create_chat')
        try:
            other_user = User.objects.get(username=username)
        except User.DoesNotExist:
            messages.error(request, "User does not exist.")
            return redirect('create_chat')
        # Optionally, you could create an initial (system) message here.
        return redirect('chat', username=other_user.username)
    return render(request, 'create_chat.html')

@login_required
def chat_redirect_view(request):
    """
    Automatically redirect to the chat_detail view for the first conversation partner.
    If no conversations exist, render an empty chat_detail page so the user can start a new chat.
    """
    msgs = Message.objects.filter(Q(sender=request.user) | Q(recipient=request.user)).order_by('-timestamp')
    partners = set()
    for msg in msgs:
        if msg.sender != request.user:
            partners.add(msg.sender)
        if msg.recipient != request.user:
            partners.add(msg.recipient)
    partners = list(partners)
    if partners:
        first_partner = partners[0]
        return redirect('chat', username=first_partner.username)
    else:
        messages.info(request, "No conversations yet. Start a new chat!")
        # Render an empty chat_detail page with no partner selected.
        context = {
            'other_user': None,
            'chat_messages': [],
            'partners': []
        }
        return render(request, 'chat_detail.html', context)

@login_required
def chat_detail_view(request, username):
    """
    Displays the conversation between the current user and the specified other user.
    Also handles sending new messages.
    """
    other_user = get_object_or_404(User, username=username)
    # Retrieve conversation partners for sidebar
    msgs = Message.objects.filter(Q(sender=request.user) | Q(recipient=request.user)).order_by('-timestamp')
    partners = set()
    for msg in msgs:
        if msg.sender != request.user:
            partners.add(msg.sender)
        if msg.recipient != request.user:
            partners.add(msg.recipient)
    partners = list(partners)
    if request.method == 'POST':
        message_text = request.POST.get('message').strip()
        if message_text:
            encrypted_text = crypto_utils.encrypt_message(message_text)
            Message.objects.create(
                sender=request.user,
                recipient=other_user,
                encrypted_text=encrypted_text
            )
            AuditLog.objects.create(
                event=f"{request.user.username} sent a message to {other_user.username}",
                user=request.user
            )
            return redirect('chat', username=username)
    # Retrieve conversation messages
    conversation = Message.objects.filter(
        (Q(sender=request.user) & Q(recipient=other_user)) |
        (Q(sender=other_user) & Q(recipient=request.user))
    ).order_by('timestamp')
    for msg in conversation:
        try:
            msg.decrypted_text = crypto_utils.decrypt_message(msg.encrypted_text)
        except Exception:
            msg.decrypted_text = "Error decrypting message."
    context = {
        'other_user': other_user,
        'chat_messages': conversation,
        'partners': partners
    }
    return render(request, 'chat_detail.html', context)

@login_required
def portfolio_history_view(request):
    now = timezone.now()
    current_minute = now.replace(second=0, microsecond=0)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if request.user.profile.role == 'advisor':
        client_profiles = Profile.objects.filter(role='client', advisor=request.user)
        portfolios = Portfolio.objects.filter(user__in=[p.user for p in client_profiles])
        # Update history for each client's portfolio
        for portfolio in portfolios:
            current_value = get_current_portfolio_value(portfolio)
            PortfolioHistory.objects.update_or_create(
                portfolio=portfolio,
                timestamp=current_minute,
                defaults={'total_value': current_value}
            )
        # Aggregate history entries across all client portfolios
        history_entries = PortfolioHistory.objects.filter(
            portfolio__in=portfolios,
            timestamp__gte=today_start
        ).values('timestamp').annotate(total=Sum('total_value')).order_by('timestamp')
        data = [{
            'timestamp': entry['timestamp'].strftime("%H:%M"),
            'total_value': float(entry['total'])
        } for entry in history_entries]
        starting_value = data[0]['total_value'] if data else sum(get_current_portfolio_value(p) for p in portfolios)
        current_value = sum(get_current_portfolio_value(p) for p in portfolios)
    else:
        portfolio = get_object_or_404(Portfolio, user=request.user)
        current_value = get_current_portfolio_value(portfolio)
        PortfolioHistory.objects.update_or_create(
            portfolio=portfolio,
            timestamp=current_minute,
            defaults={'total_value': current_value}
        )
        history_entries = PortfolioHistory.objects.filter(
            portfolio=portfolio,
            timestamp__gte=today_start
        ).order_by('timestamp')
        data = [{
            'timestamp': entry.timestamp.strftime("%H:%M"),
            'total_value': float(entry.total_value)
        } for entry in history_entries]
        starting_value = data[0]['total_value'] if data else current_value
    return JsonResponse({
        'history': data,
        'starting_value': starting_value,
        'current_value': float(current_value)
    })

def register_view(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.profile.role = form.cleaned_data.get('role')
            if user.profile.role == 'client':
                user.profile.advisor = form.cleaned_data.get('advisor')
            user.profile.save()

            AuditLog.objects.create(
                event=f"User {user.username} registered with role {user.profile.role}.",
                user=user
            )
            messages.success(request, "Registration successful. Please log in.")
            return redirect('login')
        else:
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
            for error in form.non_field_errors():
                messages.error(request, error)
            return redirect('register')
    else:
        form = RegistrationForm()
    return render(request, 'register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get("username").strip()
        password = request.POST.get("password").strip()
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            AuditLog.objects.create(
                event=f"User {username} logged in.",
                user=user
            )
            messages.success(request, f"Welcome {username}!")
            if user.profile.role == 'admin':
                return redirect('admin_dashboard')
            elif user.profile.role == 'advisor':
                return redirect('advisor')
            else:
                return redirect('portfolio')
        else:
            messages.error(request, "Invalid credentials!")
            return redirect('login')
    return render(request, 'login.html')


@login_required
def logout_view(request):
    AuditLog.objects.create(
        event=f"User {request.user.username} logged out.",
        user=request.user
    )
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('login')

@login_required
def rotate_keys_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')

    if request.method == 'POST':
        # 1) Mark old keys inactive
        PQServerKey.objects.filter(is_active=True).update(is_active=False)

        # 2) Generate a brand new key
        new_key = generate_new_key()

        # 3) Reset the cached key so the system picks up this new one
        reset_server_keys_cache()

        AuditLog.objects.create(
            event="Encryption keys rotated. Old keys archived, new key generated.",
            user=request.user
        )
        messages.success(request, "Encryption keys rotated successfully. Old keys have been archived.")
        return redirect('admin_dashboard')

    return render(request, 'rotate_keys_confirm.html')

@login_required
def message(request):  # Ensure Message model is imported
    if request.method == 'POST':
        recipient_username = request.POST.get('recipient').strip()
        message_text = request.POST.get('message').strip()
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            messages.error(request, "Recipient does not exist.")
            return redirect('message')
        # Encrypt the message text
        encrypted_text = crypto_utils.encrypt_message(message_text)
        Message.objects.create(
            sender=request.user,
            recipient=recipient,
            encrypted_text=encrypted_text
        )
        messages.success(request, "Message sent.")
        return redirect('message')
    else:
        # Retrieve messages where current user is sender or recipient.
        chat_messages = Message.objects.filter(sender=request.user) | Message.objects.filter(recipient=request.user)
        chat_messages = chat_messages.order_by('timestamp')
        # Decrypt each message for display
        for msg in chat_messages:
            try:
                msg.decrypted_text = crypto_utils.decrypt_message(msg.encrypted_text)
            except Exception as e:
                msg.decrypted_text = "Error decrypting message."
        context = {'chat_messages': chat_messages}
        return render(request, 'chat.html', context)


def get_current_portfolio_value(portfolio):
    # Start with cash balance.
    total = Decimal(portfolio.user.profile.balance)
    # Add value of each holding using the stock's last_price (if available).
    for holding in portfolio.holdings.all():
        if holding.stock.last_price:
            total += holding.shares * holding.stock.last_price
    return total

@login_required
def portfolio_view(request):
    portfolio, _ = Portfolio.objects.get_or_create(user=request.user)
    holdings = portfolio.holdings.all()
    user_balance = request.user.profile.balance  # Keep as Decimal
    total_holdings_value = Decimal('0')
    holding_data = []

    for holding in holdings:
        price = holding.stock.last_price if holding.stock.last_price is not None else Decimal('0')
        value = holding.shares * price
        total_holdings_value += value
        holding_data.append({
            'holding': holding,
            'value': value,  # Decimal
            'percentage': Decimal('0'),
        })

    total_portfolio_value = user_balance + total_holdings_value
    cash_percentage = (user_balance / total_portfolio_value * Decimal('100')) if total_portfolio_value > 0 else Decimal('0')

    # Build chart data; convert to float only when preparing JSON.
    chart_data = [{
        "label": "Cash",
        "value": float(user_balance),
        "percentage": float(cash_percentage)
    }]
    for item in holding_data:
        pct = (item['value'] / total_portfolio_value * Decimal('100')) if total_portfolio_value > 0 else Decimal('0')
        item['percentage'] = pct
        chart_data.append({
            "label": item['holding'].stock.ticker,
            "value": float(item['value']),
            "percentage": float(pct)
        })

    stocks = Stock.objects.all().order_by('ticker')
    context = {
        'portfolio': portfolio,
        'holdings': holdings,
        'holding_data': holding_data,  # May be used in the template (as Decimals)
        'chart_data': json.dumps(chart_data),
        'total_portfolio_value': float(total_portfolio_value),
        'cash_percentage': float(cash_percentage),
        'cash_balance': float(user_balance),
        'stocks': stocks,
    }
    return render(request, 'portfolio.html', context)



@login_required
def stock_list_view(request):
    default_tickers = [
        "AAPL", "MSFT", "GOOGL", "AMZN", "TSLA","BRK-B", "JNJ", "V", "WMT", "JPM",
        "PG", "MA", "NVDA", "HD", "DIS", "BAC", "XOM", "VZ", "ADBE", "NFLX"
    ]
    current_count = Stock.objects.count()
    if current_count < 20:
        for ticker in default_tickers:
            try:
                yf_ticker = yf.Ticker(ticker)
                info = yf_ticker.info
                company_name = info.get('shortName') or info.get('longName') or ticker
                history = yf_ticker.history(period="1d")
                if not history.empty:
                    last_price = history['Close'].iloc[-1]
                else:
                    last_price = None

                Stock.objects.update_or_create(
                    ticker=ticker,
                    defaults={
                        'company_name': company_name,
                        'last_price': last_price,
                        'last_updated': timezone.now()
                    }
                )
            except Exception as e:
                print(f"Error updating {ticker}: {e}")
    stocks = Stock.objects.all().order_by('ticker')
    stock_data = []
    for stock in stocks:
        update_required = True
        if stock.last_updated:
            delta = timezone.now() - stock.last_updated
            if delta.total_seconds() < 60:
                update_required = False
        if update_required:
            try:
                yf_ticker = yf.Ticker(stock.ticker)
                history = yf_ticker.history(period="1d")
                if not history.empty:
                    last_price = history['Close'].iloc[-1]
                else:
                    last_price = stock.last_price
                stock.last_price = last_price
                stock.last_updated = timezone.now()
                stock.save()
            except Exception as e:
                print(f"Error updating {stock.ticker}: {e}")
                last_price = stock.last_price
        else:
            last_price = stock.last_price
        stock_data.append({
            'ticker': stock.ticker,
            'company_name': stock.company_name,
            'last_price': last_price,
        })
    return render(request, 'stock_list.html', {'stocks': stock_data})

@login_required
def invest_view(request, ticker):
    stock = get_object_or_404(Stock, ticker=ticker)
    portfolio = get_object_or_404(Portfolio, user=request.user)

    if request.method == 'POST':
        form = InvestForm(request.POST)
        if form.is_valid():
            shares = form.cleaned_data['shares']
            try:
                price = yf.Ticker(stock.ticker).history(period="1d")['Close'].iloc[-1]
            except Exception:
                messages.error(request, "Failed to retrieve stock price.")
                return redirect('stock_list')

            total_cost = shares * Decimal(str(price))

            # *** Use the user’s Profile’s encrypted balance ***
            profile = request.user.profile
            if profile.balance < total_cost:
                messages.error(request, "Insufficient funds.")
                return redirect('invest', ticker=ticker)

            # Subtract funds from the encrypted balance
            profile.balance = profile.balance - total_cost
            profile.save()

            # Update (or create) the user's Holding
            holding, _ = Holding.objects.get_or_create(portfolio=portfolio, stock=stock)
            holding.shares += shares
            holding.save()

            # Prepare the encrypted fields
            from .models import PQServerKey
            key_obj = PQServerKey.objects.filter(is_active=True).first()

            timestamp = int(time.time())
            encrypted_stock = encrypt_field(stock.ticker, b'investment_stock', b'investment stock encryption')
            encrypted_type = encrypt_field('BUY', b'investment_type', b'investment type encryption')
            encrypted_shares = encrypt_field(str(shares), b'investment_shares', b'investment shares encryption')
            encrypted_price = encrypt_field(str(price), b'investment_price', b'investment price encryption')
            encrypted_ts = encrypt_field(str(timestamp), b'investment_timestamp', b'investment timestamp encryption')

            # Store the transaction referencing the exact key used
            InvestmentTransaction.objects.create(
                portfolio=portfolio,
                encrypted_stock=encrypted_stock,
                encrypted_transaction_type=encrypted_type,
                encrypted_shares=encrypted_shares,
                encrypted_price=encrypted_price,
                encrypted_timestamp=encrypted_ts,
                key_used=key_obj,  # new
            )

            messages.success(request, f"Purchased {shares} shares of {stock.ticker} at £{price:.2f}.")
            return redirect('portfolio')
    else:
        form = InvestForm()

    return render(request, 'invest.html', {'stock': stock, 'form': form})


@login_required
def admin_dashboard_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    users = User.objects.all().order_by('username')
    audit_logs = AuditLog.objects.all().order_by('-timestamp')[:5]
    # Active server key for fallback
    algorithm, active_pub_key, active_server_priv = get_server_keys()
    server_public_key = base64.b64encode(active_pub_key).decode('utf-8')
    decrypted_transactions = []
    total_money = Decimal('0')
    valid_count = 0
    transactions = InvestmentTransaction.objects.all().order_by('-timestamp')
    for tx in transactions[:5]:
        try:
            # Use the correct key
            if tx.key_used:
                local_priv = base64.b64decode(tx.key_used.private_key)
            else:
                local_priv = active_server_priv
            decrypted_stock = decrypt_field(tx.encrypted_stock, b'investment_stock',
                                             b'investment stock encryption', local_priv)
            decrypted_type = decrypt_field(tx.encrypted_transaction_type, b'investment_type',
                                            b'investment type encryption', local_priv)
            shares_str = decrypt_field(tx.encrypted_shares, b'investment_shares',
                                        b'investment shares encryption', local_priv)
            price_str = decrypt_field(tx.encrypted_price, b'investment_price',
                                       b'investment price encryption', local_priv)
            shares = Decimal(shares_str)
            price = Decimal(price_str)
            total_money += shares * price
            valid_count += 1
            tx_display = {
                'id': tx.id,
                'stock': decrypted_stock,
                'transaction_type': decrypted_type,
                'shares': shares,
                'price': price,
                'timestamp': tx.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            # If decryption fails, show placeholders
            tx_display = {
                'id': tx.id,
                'stock': "Error",
                'transaction_type': "Error",
                'shares': "Error",
                'price': "Error",
                'timestamp': tx.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
        decrypted_transactions.append(tx_display)
    total_transactions = transactions.count()
    average_transaction = total_money / valid_count if valid_count else Decimal('0')
    context = {
        'users': users,
        'audit_logs': audit_logs,
        'recent_transactions': decrypted_transactions,
        'server_algorithm': algorithm,
        'server_public_key': server_public_key,
        'analytics': {
            'total_transactions': total_transactions,
            'total_money_moved': total_money,
            'average_transaction': average_transaction,
        },
    }
    return render(request, 'admin_dashboard.html', context)



@login_required
def admin_user_detail_view(request, user_id):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    user_obj = get_object_or_404(User, id=user_id)
    profile = user_obj.profile
    portfolio, created = Portfolio.objects.get_or_create(user=user_obj)
    holdings = portfolio.holdings.all()
    
    # Use Decimal arithmetic
    cash = profile.balance  # Decimal
    total_holdings_value = Decimal('0')
    holding_data = []
    for holding in holdings:
        if holding.stock.last_price:
            value = holding.shares * holding.stock.last_price
        else:
            value = Decimal('0')
        total_holdings_value += value
        holding_data.append({
            'holding': holding,
            'value': value,
            'percentage': Decimal('0'),
        })
    total_portfolio_value = cash + total_holdings_value
    cash_percentage = (cash / total_portfolio_value * Decimal('100')) if total_portfolio_value > 0 else Decimal('0')
    for item in holding_data:
        item['percentage'] = (item['value'] / total_portfolio_value * Decimal('100')) if total_portfolio_value > 0 else Decimal('0')
    
    # Prepare chart data (convert Decimals to float for serialization)
    chart_data = [{
        "label": "Cash",
        "value": float(cash),
        "percentage": float(cash_percentage)
    }]
    for item in holding_data:
        chart_data.append({
            "label": item['holding'].stock.ticker,
            "value": float(item['value']),
            "percentage": float(item['percentage'])
        })
    
    extra_info = {}
    if profile.role == 'client':
        extra_info['advisor'] = profile.advisor
    elif profile.role == 'advisor':
        extra_info['clients_assigned'] = Profile.objects.filter(
            role='client', advisor=user_obj
        ).order_by('user__username')
    
    context = {
        'user_obj': user_obj,
        'portfolio': portfolio,
        'holding_data': holding_data,
        'chart_data': json.dumps(chart_data),
        'total_portfolio_value': float(total_portfolio_value),
        'cash_percentage': float(cash_percentage),
        'profile_role': profile.role,
        'cash': float(cash),
    }
    context.update(extra_info)
    return render(request, 'admin_user_detail.html', context)


@login_required
def admin_user_delete_view(request, user_id):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    user_obj = get_object_or_404(User, id=user_id)
    if request.method == 'POST':
        AuditLog.objects.create(
            event=f"User {user_obj.username} deleted by admin {request.user.username}.",
            user=request.user
        )
        user_obj.delete()
        messages.success(request, f"User {user_obj.username} deleted successfully.")
        return redirect('admin_dashboard')
    return render(request, 'admin_user_delete_confirm.html', {'user_obj': user_obj})

@login_required
def admin_create_user_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()  # This triggers the signal, which will create the Profile & Portfolio

            # set custom role & advisor from the form
            user.profile.role = form.cleaned_data.get('role')
            if user.profile.role == 'client':
                user.profile.advisor = form.cleaned_data.get('advisor')
            user.profile.save()

            AuditLog.objects.create(
                event=f"Admin {request.user.username} created user {user.username}.",
                user=request.user
            )
            messages.success(request, f"User {user.username} created successfully.")
            return redirect('admin_dashboard')
        else:
            for field in form:
                for error in field.errors:
                    messages.error(request, f"{field.label}: {error}")
            for error in form.non_field_errors():
                messages.error(request, error)
            return redirect('admin_create_user')
    else:
        form = RegistrationForm()
    return render(request, 'admin_create_user.html', {'form': form})



@login_required
def clear_db_view(request):
    if request.user.profile.role != 'admin':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    from .models import PQServerKey
    InvestmentTransaction.objects.all().delete()
    PQServerKey.objects.all().delete()
    crypto_utils.ensure_server_key()
    AuditLog.objects.create(
        event="Database cleared and re-initialized by admin.",
        user=request.user
    )
    messages.info(request, "Database cleared and re-initialized.")
    return redirect('portfolio')

@login_required
def advisor_view(request):
    stocks = Stock.objects.all().order_by('ticker')
    if request.user.profile.role != 'advisor':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    client_profiles = Profile.objects.filter(role='client', advisor=request.user).order_by('user__username')
    clients_data = []
    total_cash = Decimal('0')
    stock_totals = {}
    for client in client_profiles:
        portfolio, _ = Portfolio.objects.get_or_create(user=client.user)
        cash = portfolio.user.profile.balance  # Decimal
        total_holdings_value = Decimal('0')
        for holding in portfolio.holdings.all():
            price = holding.stock.last_price if holding.stock.last_price is not None else Decimal('0')
            total_holdings_value += holding.shares * price
        portfolio_value = cash + total_holdings_value
        total_cash += cash
        for holding in portfolio.holdings.all():
            ticker = holding.stock.ticker
            price = holding.stock.last_price if holding.stock.last_price is not None else Decimal('0')
            if ticker in stock_totals:
                stock_totals[ticker]['shares'] += holding.shares
            else:
                stock_totals[ticker] = {
                    'shares': holding.shares,
                    'price': price,
                    'company_name': holding.stock.company_name
                }
        clients_data.append({
            'user': client.user,
            'portfolio_value': portfolio_value,
        })
    chart_data = [{
        'label': "Cash",
        'value': total_cash
    }]
    for ticker, data in stock_totals.items():
        total_value = data['shares'] * data['price']
        chart_data.append({
            'label': ticker,
            'value': total_value,
            'shares': data['shares'],
            'company_name': data['company_name']
        })
    total_combined_value = total_cash + sum(item['value'] for item in chart_data if item['label'] != "Cash")
    for item in chart_data:
        item['percentage'] = (item['value'] / total_combined_value * Decimal('100')) if total_combined_value > 0 else Decimal('0')
    
    # Serialize chart data for JSON (convert Decimals to float)
    chart_data_serialized = []
    for item in chart_data:
        chart_data_serialized.append({
            'label': item['label'],
            'value': float(item['value']),
            'percentage': float(item['percentage']),
            'shares': float(item['shares']) if 'shares' in item else None,
            'company_name': item.get('company_name', '')
        })
    context = {
        'clients': clients_data,
        'stocks': stocks,
        'chart_data': json.dumps(chart_data_serialized),
    }
    return render(request, 'advisor.html', context)



@login_required
def advisor_transaction_view(request):
    if request.user.profile.role != 'advisor':
        messages.error(request, "Access denied.")
        return redirect('portfolio')

    if request.method == 'POST':
        client_id = request.POST.get("client")
        ticker = request.POST.get("ticker", "").strip().upper()
        shares_input = request.POST.get("shares")
        action = request.POST.get("action")  # "buy" or "sell"

        # Validate shares input
        try:
            shares = Decimal(shares_input)
        except Exception:
            messages.error(request, "Invalid share amount.")
            return redirect('advisor')

        # Fetch client profile that belongs to this advisor
        try:
            client_profile = Profile.objects.get(user__id=client_id, role='client', advisor=request.user)
            client_user = client_profile.user
        except Profile.DoesNotExist:
            messages.error(request, "Client not found or is not assigned to you.")
            return redirect('advisor')

        # Get the client's portfolio
        portfolio, _ = Portfolio.objects.get_or_create(user=client_user)

        # Retrieve the stock instance
        try:
            stock = Stock.objects.get(ticker=ticker)
        except Stock.DoesNotExist:
            messages.error(request, f"Stock '{ticker}' not found.")
            return redirect('advisor')

        # Retrieve the current stock price using yfinance
        try:
            yf_ticker = yf.Ticker(stock.ticker)
            history = yf_ticker.history(period="1d")
            if not history.empty:
                price = Decimal(str(history['Close'].iloc[-1]))
            else:
                messages.error(request, f"Stock price not available for {ticker}.")
                return redirect('advisor')
        except Exception:
            messages.error(request, "Error retrieving stock data.")
            return redirect('advisor')

        # Retrieve the active encryption key
        key_obj = PQServerKey.objects.filter(is_active=True).first()
        if not key_obj:
            messages.error(request, "No active encryption key found. Cannot record transaction.")
            return redirect('advisor')

        # Common fields for encryption
        timestamp_str = str(int(time.time()))

        if action == 'buy':
            if shares <= 0:
                messages.error(request, "Must buy at least 0.01 share.")
                return redirect('advisor')
            total_cost = shares * price
            # Ensure the client has enough balance
            if client_profile.balance < total_cost:
                messages.error(request, "Client has insufficient funds for this purchase.")
                return redirect('advisor')

            # Deduct the cost from the client's encrypted balance
            client_profile.balance = client_profile.balance - total_cost
            client_profile.save()

            # Update or create the holding
            holding, created = Holding.objects.get_or_create(
                portfolio=portfolio,
                stock=stock,
                defaults={'shares': Decimal('0')}
            )
            holding.shares += shares
            holding.save()

            # Encrypt transaction details
            e_stock = encrypt_field(stock.ticker, b'investment_stock', b'investment stock encryption')
            e_type = encrypt_field('BUY', b'investment_type', b'investment type encryption')
            e_shares = encrypt_field(str(shares), b'investment_shares', b'investment shares encryption')
            e_price = encrypt_field(str(price), b'investment_price', b'investment price encryption')
            e_ts = encrypt_field(timestamp_str, b'investment_timestamp', b'investment timestamp encryption')

            # Create the investment transaction record
            InvestmentTransaction.objects.create(
                portfolio=portfolio,
                encrypted_stock=e_stock,
                encrypted_transaction_type=e_type,
                encrypted_shares=e_shares,
                encrypted_price=e_price,
                encrypted_timestamp=e_ts,
                key_used=key_obj,
            )

            # Log the event
            AuditLog.objects.create(
                event=(
                    f"Advisor {request.user.username} bought {shares} shares of {ticker} "
                    f"at £{price:.2f} for client {client_user.username}."
                ),
                user=request.user
            )

            messages.success(
                request,
                f"Bought {shares} shares of {ticker} for {client_user.username} at £{price:.2f} per share."
            )

        elif action == 'sell':
            # Ensure the client actually holds that stock
            if shares <= 0:
                messages.error(request, "Must sell at least 0.01 share.")
                return redirect('advisor')
            holding = Holding.objects.filter(portfolio=portfolio, stock=stock).first()
            if not holding:
                messages.error(request, "Client does not hold this stock.")
                return redirect('advisor')
            if holding.shares < shares:
                messages.error(request, "Client does not have enough shares to sell.")
                return redirect('advisor')

            # Calculate total sale proceeds
            total_sale = shares * price

            # Increase the client's encrypted balance
            client_profile.balance = client_profile.balance + total_sale
            client_profile.save()
            holding.shares -= shares
            if holding.shares == 0:
                 holding.delete()
            else:
                 holding.save()
        

            # Encrypt transaction details
            e_stock = encrypt_field(stock.ticker, b'investment_stock', b'investment stock encryption')
            e_type = encrypt_field('SELL', b'investment_type', b'investment type encryption')
            e_shares = encrypt_field(str(shares), b'investment_shares', b'investment shares encryption')
            e_price = encrypt_field(str(price), b'investment_price', b'investment price encryption')
            e_ts = encrypt_field(timestamp_str, b'investment_timestamp', b'investment timestamp encryption')

            # Create the transaction record
            InvestmentTransaction.objects.create(
                portfolio=portfolio,
                encrypted_stock=e_stock,
                encrypted_transaction_type=e_type,
                encrypted_shares=e_shares,
                encrypted_price=e_price,
                encrypted_timestamp=e_ts,
                key_used=key_obj,
            )

            # Log the event
            AuditLog.objects.create(
                event=(
                    f"Advisor {request.user.username} sold {shares} shares of {ticker} "
                    f"at £{price:.2f} for client {client_user.username}."
                ),
                user=request.user
            )

            messages.success(
                request,
                f"Sold {shares} shares of {ticker} for {client_user.username} at £{price:.2f} per share."
            )

        else:
            messages.error(request, "Invalid transaction action.")

        # Redirect back to the advisor page
        return redirect('advisor')

    else:
        # GET request: Show the transaction form with clients & stocks
        clients = Profile.objects.filter(role='client', advisor=request.user).order_by('user__username')
        stocks = Stock.objects.all().order_by('ticker')
        context = {
            'clients': clients,
            'stocks': stocks,
        }
        return render(request, 'advisor_transaction.html', context)

@login_required
def advisor_client_detail_view(request, client_id):
    if request.user.profile.role != 'advisor':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    client_profile = get_object_or_404(Profile, user__id=client_id, role='client', advisor=request.user)
    portfolio, _ = Portfolio.objects.get_or_create(user=client_profile.user)
    holdings = portfolio.holdings.all()
    cash = client_profile.balance  # Decimal
    total_holdings_value = Decimal('0')
    holding_data = []
    for holding in holdings:
        if holding.stock.last_price:
            value = holding.shares * holding.stock.last_price
        else:
            value = Decimal('0')
        total_holdings_value += value
        holding_data.append({
            'holding': holding,
            'value': value,
            'percentage': Decimal('0'),
        })
    total_portfolio_value = cash + total_holdings_value
    cash_percentage = (cash / total_portfolio_value * Decimal('100')) if total_portfolio_value > 0 else Decimal('0')
    for item in holding_data:
        item['percentage'] = (item['value'] / total_portfolio_value * Decimal('100')) if total_portfolio_value > 0 else Decimal('0')
    
    chart_data = [{
        "label": "Cash",
        "value": cash,
        "percentage": cash_percentage
    }]
    for item in holding_data:
        chart_data.append({
            "label": item['holding'].stock.ticker,
            "value": item['value'],
            "percentage": item['percentage']
        })
    # Serialize chart data for JSON output.
    chart_data_serialized = []
    for item in chart_data:
        chart_data_serialized.append({
            "label": item["label"],
            "value": float(item["value"]),
            "percentage": float(item["percentage"])
        })
    context = {
        'client_profile': client_profile,
        'portfolio': portfolio,
        'holding_data': holding_data,
        'chart_data': json.dumps(chart_data_serialized),
        'total_portfolio_value': float(total_portfolio_value),
        'cash_percentage': float(cash_percentage),
        'cash_balance': float(cash),
    }
    return render(request, 'advisor_client_detail.html', context)



@login_required
def advisor_message_view(request):
    # Only advisors can send investment recommendations.
    if request.user.profile.role != 'advisor':
        messages.error(request, "Access denied.")
        return redirect('portfolio')
    
    if request.method == 'POST':
        recipient_username = request.POST.get("recipient").strip()
        message_text = request.POST.get("message").strip()
        
        if not recipient_username or not message_text:
            messages.error(request, "Both recipient and message are required.")
            return redirect('advisor_message')
        
        try:
            recipient = User.objects.get(username=recipient_username)
        except User.DoesNotExist:
            messages.error(request, "Client not found.")
            return redirect('advisor_message')
        
        # Encrypt the message using crypto_utils function.
        encrypted_text = crypto_utils.encrypt_message(message_text)
        Message.objects.create(
            sender=request.user,
            recipient=recipient,
            encrypted_text=encrypted_text
        )
        
        AuditLog.objects.create(
            event=f"Advisor {request.user.username} sent a recommendation to {recipient.username}.",
            user=request.user
        )
        
        messages.success(request, "Recommendation sent successfully.")
        # Redirect to the chat detail view for this recipient.
        return redirect('chat', username=recipient.username)
    
    # For GET requests, render the message form.
    return render(request, 'advisor_message.html')

@login_required
def client_transaction_view(request):
    if request.user.profile.role != 'client':
        messages.error(request, "ACCESS DENIED. Clients only.")
        return redirect('portfolio')
    portfolio, _ = Portfolio.objects.get_or_create(user=request.user)
    if request.method == 'POST':
        ticker = request.POST.get("ticker", "").strip().upper()
        shares_input = request.POST.get("shares")
        action = request.POST.get("action")  # "buy" or "sell"
        try:
            shares = Decimal(shares_input)
        except:
            messages.error(request, "Invalid share amount.")
            return redirect('portfolio')
        try:
            stock = Stock.objects.get(ticker=ticker)
        except Stock.DoesNotExist:
            messages.error(request, f"Stock '{ticker}' not found.")
            return redirect('portfolio')
        # Retrieve current price
        try:
            price = Decimal(str(yf.Ticker(stock.ticker).history(period="1d")['Close'].iloc[-1])) # Retrieve current price
        except:
            messages.error(request, "Unable to retrieve stock data.")
            return redirect('portfolio')

        profile = request.user.profile
        timestamp = int(time.time())

        from .models import PQServerKey
        key_obj = PQServerKey.objects.filter(is_active=True).first()

        if action == 'buy':
            if shares <= 0:
                messages.error(request, "Must buy at least 0.01 share.")
                return redirect('portfolio')
            total_cost = shares * price
            if profile.balance < total_cost:
                messages.error(request, "Insufficient funds.")
                return redirect('portfolio')

            # Subtract from encrypted balance
            profile.balance = profile.balance - total_cost
            profile.save()

            # Increase holding
            holding, _ = Holding.objects.get_or_create(portfolio=portfolio, stock=stock)
            holding.shares += shares
            holding.save()

            # Encrypt fields
            e_stock = encrypt_field(stock.ticker, b'investment_stock', b'investment stock encryption')
            e_type = encrypt_field('BUY', b'investment_type', b'investment type encryption')
            e_shares = encrypt_field(str(shares), b'investment_shares', b'investment shares encryption')
            e_price = encrypt_field(str(price), b'investment_price', b'investment price encryption')
            e_ts = encrypt_field(str(timestamp), b'investment_timestamp', b'investment timestamp encryption')

            # Save transaction
            InvestmentTransaction.objects.create(
                portfolio=portfolio,
                encrypted_stock=e_stock,
                encrypted_transaction_type=e_type,
                encrypted_shares=e_shares,
                encrypted_price=e_price,
                encrypted_timestamp=e_ts,
                key_used=key_obj,
            )
            messages.success(request, f"Purchased {shares} shares of {ticker} at £{price:.2f}.")

        elif action == 'sell':
            if shares <= 0:
                messages.error(request, "Must sell at least 0.01 share.")
                return redirect('portfolio')
            holding = Holding.objects.filter(portfolio=portfolio, stock=stock).first()
            if not holding or holding.shares < shares:
                messages.error(request, "Not enough shares to sell.")
                return redirect('portfolio')

            total_sale = shares * price
            # Add to the encrypted balance
            profile.balance = profile.balance + total_sale
            profile.save()
            holding.shares -= shares
            if holding.shares == 0.00:
                holding.delete()
            else:
                holding.save()


            e_stock = encrypt_field(stock.ticker, b'investment_stock', b'investment stock encryption')
            e_type = encrypt_field('SELL', b'investment_type', b'investment type encryption')
            e_shares = encrypt_field(str(shares), b'investment_shares', b'investment shares encryption')
            e_price = encrypt_field(str(price), b'investment_price', b'investment price encryption')
            e_ts = encrypt_field(str(timestamp), b'investment_timestamp', b'investment timestamp encryption')

            InvestmentTransaction.objects.create(
                portfolio=portfolio,
                encrypted_stock=e_stock,
                encrypted_transaction_type=e_type,
                encrypted_shares=e_shares,
                encrypted_price=e_price,
                encrypted_timestamp=e_ts,
                key_used=key_obj,
            )
            messages.success(request, f"Sold {shares} shares of {ticker} at £{price:.2f}.")
        else:
            messages.error(request, "Invalid transaction action.")

        return redirect('portfolio')

    # GET request
    stocks = Stock.objects.all().order_by('ticker')
    return render(request, 'client_transaction.html', {'stocks': stocks, 'portfolio': portfolio})
