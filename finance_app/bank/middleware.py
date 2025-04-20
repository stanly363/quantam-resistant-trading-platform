# bank/middleware.py

from django.core.cache import cache
from django.http import HttpResponse
from django.utils.deprecation import MiddlewareMixin

def check_rate_limit(request, rate='100/h'):
    try:
        count_str, period = rate.split('/')
        count = int(count_str)
    except ValueError:
        # Fallback to a default if rate is misconfigured
        count = 100
        period = 'h'
    # Determine the period in seconds
    if period == 'h':
        seconds = 3600
    elif period == 'm':
        seconds = 60
    else:
        seconds = 1  # Default: 1 second
    ip = request.META.get('REMOTE_ADDR', 'unknown')
    cache_key = f"ratelimit:{ip}"

    current = cache.get(cache_key)
    if current is None:
        cache.set(cache_key, 1, timeout=seconds)
        return False
    else:
        if current >= count:
            return True  # Rate limit exceeded
        else:
            try:
                # Increase the counter
                cache.incr(cache_key)
            except ValueError:
                # In case the key expired between get and incr, set it again.
                cache.set(cache_key, 1, timeout=seconds)
            return False

class GlobalRateLimitMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Check rate limit: set to 100 requests per minute per IP
        if check_rate_limit(request, rate='100/m'):
            return HttpResponse("Too many requests. Please try again later.", status=429)
        # Continue processing the view if limit not exceeded.
        return None

