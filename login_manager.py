from flask_login import LoginManager, current_user
from functools import wraps
from datetime import datetime, timedelta
from flask import abort, session, redirect, url_for, flash, request, render_template
import secrets
import re

class EnhancedLoginManager:
    def __init__(self, app=None):
        self.login_manager = LoginManager()
        self.login_manager.session_protection = "strong"
        self.max_failed_attempts = 3
        self.lockout_duration = timedelta(minutes=15)
        self.password_reset_timeout = timedelta(hours=1)
        
        if app:
            self.init_app(app)

    def init_app(self, app):
        # Basic security configurations
        app.config.update(
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
            REMEMBER_COOKIE_DURATION=timedelta(days=14),
            REMEMBER_COOKIE_SECURE=True,
            REMEMBER_COOKIE_HTTPONLY=True,
            REMEMBER_COOKIE_SAMESITE='Lax'
        )
        
        self.login_manager.init_app(app)
        self.login_manager.login_view = 'login'
        self.login_manager.login_message = 'Please log in to access this page.'
        self.login_manager.login_message_category = 'warning'
        self.login_manager.needs_refresh_message = 'Please reauthenticate to protect your account.'
        self.login_manager.needs_refresh_message_category = 'warning'
    
        # Set up session protection
        @app.before_request
        def before_request():
            if current_user.is_authenticated:
                # Check session age
                if 'last_active' in session:
                    last_active = datetime.fromisoformat(session['last_active'])
                    if datetime.now() - last_active > timedelta(minutes=30):
                        session.clear()
                        return redirect(url_for('login'))
                
                # Update last active timestamp
                session['last_active'] = datetime.now().isoformat()
                
                # Rotate session ID periodically
                if 'session_created' not in session:
                    session['session_created'] = datetime.now().isoformat()
                else:
                    created = datetime.fromisoformat(session['session_created'])
                    if datetime.now() - created > timedelta(hours=1):
                        session.clear()
                        session['session_created'] = datetime.now().isoformat()
    
    def user_loader(self, callback):
        self.login_manager.user_loader(callback)

    def authorize_login(self, user, password):
        if not user:
            return False, "Invalid username or password"

        # Check if account is locked
        if hasattr(user, 'locked_until') and user.locked_until:
            if datetime.now() < user.locked_until:
                remaining = (user.locked_until - datetime.now()).seconds // 60
                return False, f"Account is locked for {remaining} more minutes"
            else:
                # Reset locked_until and failed_attempts
                user.locked_until = None
                user.failed_attempts = 0

        # Validate password
        if not self.verify_password(user, password):
            user.failed_attempts += 1

            if user.failed_attempts >= self.max_failed_attempts:
                user.locked_until = datetime.now() + self.lockout_duration
                return False, f"Account locked for {self.lockout_duration.seconds // 60} minutes due to too many failed attempts"
            else:
                remaining = self.max_failed_attempts - user.failed_attempts
                return False, f"Invalid password. {remaining} attempts remaining"

        # Successful login
        user.failed_attempts = 0
        user.locked_until = None
        return True, "Login successful"


    def verify_password(self, user, password):
        """
        Verify password with constant-time comparison
        Override this method for custom password verification
        """
        from werkzeug.security import check_password_hash
        return check_password_hash(user.password, password)

    def require_fresh_login(self, view_function):
        """
        Decorator to require fresh login for sensitive operations
        """
        @wraps(view_function)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            # Check if login is fresh (within last 10 minutes)
            if 'login_fresh' not in session or \
               datetime.now() - datetime.fromisoformat(session['login_fresh']) > timedelta(minutes=10):
                flash('Please re-authenticate for this sensitive operation', 'warning')
                return redirect(url_for('login', next=request.url))
                
            return view_function(*args, **kwargs)
        return decorated_view

    def require_role(self, required_role):
        """
        Decorator to require specific role for access
        """
        def decorator(view_function):
            @wraps(view_function)
            def decorated_view(*args, **kwargs):
                if not current_user.is_authenticated:
                    return redirect(url_for('login'))
                
                if not hasattr(current_user, 'role') or current_user.role != required_role:
                    abort(403)
                    
                return view_function(*args, **kwargs)
            return decorated_view
        return decorator