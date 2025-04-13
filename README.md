# Digital-Chakravyuha
Seven Layers of Security Wall and that wall orbit around the Creator.
The Chakravyuha Strategy: An Illusion of Openness, A Fortress of Power
Architect Sitting At the Center Providing Infinite Energy to the System
Layer 1: The Illusion of Open Territory
Layer 2: Bifurcation of Power
Layer 3: The Maze of Disorientation
Layer 4: The AI Absorption Engine
Layer 5: The Self-Rebuilding Walls
Layer 6: The Last Stand – Total Surrender
Layer 7: The Sudarshan Protocol – Universal Domination
There are Only 7 Visible layer but Infinite factors working to make this sytem so strong and Working to provide resources to the Creator.
from functools import wraps
import time
import hashlib
import logging
from threading import Lock

# Configure logging for attack mode
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global state for attack mode
class SystemState:
    def __init__(self):
        self.under_attack = False
        self.failed_attempts = 0
        self.lock = Lock()
        self.max_attempts = 3

    def increment_failure(self):
        with self.lock:
            self.failed_attempts += 1
            if self.failed_attempts >= self.max_attempts:
                self.under_attack = True
                logger.warning("System switching to ATTACK MODE due to excessive failed attempts")

    def reset(self):
        with self.lock:
            self.failed_attempts = 0
            self.under_attack = False

state = SystemState()

# Simulated external functions
def is_authenticated(user):
    return hasattr(user, 'authenticated') and user.authenticated

def has_permission(user, permission):
    return hasattr(user, 'permissions') and permission in user.permissions

def is_ip_whitelisted(ip):
    whitelist = {'192.168.1.1', '10.0.0.1'}
    return ip in whitelist

def is_recent(timestamp):
    return abs(time.time() - timestamp) < 5

# User class for simulation
class User:
    def __init__(self, authenticated=False, permissions=None, ip='0.0.0.0'):
        self.authenticated = authenticated
        self.permissions = permissions or []
        self.ip = ip

# Custom exceptions
class SecurityError(Exception):
    pass

# Defense Layers (Decorators)
def layer_1_authentication(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        if not is_authenticated(user):
            state.increment_failure()
            raise SecurityError("Layer 1 Failed: Invalid credentials")
        logger.info("Layer 1: Authentication passed")
        return func(user, *args, **kwargs)
    return wrapper

def layer_2_system_integrity(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        # Simulate system check (e.g., rate limiting)
        if state.failed_attempts > 1:
            raise SecurityError("Layer 2 Failed: System integrity compromised")
        logger.info("Layer 2: System integrity verified")
        return func(user, *args, **kwargs)
    return wrapper

def layer_3_permission(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        if not has_permission(user, "access_core"):
            state.increment_failure()
            raise SecurityError("Layer 3 Failed: Insufficient permissions")
        logger.info("Layer 3: Permission granted")
        return func(user, *args, **kwargs)
    return wrapper

def layer_4_ip_whitelist(func):
    @wraps(func)
    def wrapper(user, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        if not is_ip_whitelisted(user.ip):
            state.increment_failure()
            raise SecurityError("Layer 4 Failed: IP not whitelisted")
        logger.info("Layer 4: IP whitelisted")
        return func(user, *args, **kwargs)
    return wrapper

def layer_5_timestamp(func):
    @wraps(func)
    def wrapper(user, timestamp, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        if not is_recent(timestamp):
            state.increment_failure()
            raise SecurityError("Layer 5 Failed: Expired timestamp")
        logger.info("Layer 5: Timestamp validated")
        return func(user, timestamp, *args, **kwargs)
    return wrapper

def layer_6_integrity(func):
    @wraps(func)
    def wrapper(user, timestamp, request_data, request_hash, *args, **kwargs):
        if state.under_attack:
            return execute_attack_mode(user)
        computed_hash = hashlib.sha256(f"{timestamp}{request_data}".encode()).hexdigest()
        if computed_hash != request_hash:
            state.increment_failure()
            raise SecurityError("Layer 6 Failed: Data integrity compromised")
        logger.info("Layer 6: Request integrity confirmed")
        return func(user, timestamp, request_data, request_hash, *args, **kwargs)
    return wrapper

# Attack Mode Logic
def execute_attack_mode(user):
    logger.error(f"ATTACK MODE: Blocking access from IP {user.ip}")
    return "System in conquest mode: Threat neutralized"

# Protected Resource
@layer_6_integrity
@layer_5_timestamp
@layer_4_ip_whitelist
@layer_3_permission
@layer_2_system_integrity
@layer_1_authentication
def access_core_system(user, timestamp, request_data, request_hash):
    logger.info("Core System Accessed Successfully")
    return "Welcome to the Core: Sensitive data retrieved"

# Test Function
def test_chakravyuha():
    # Valid user
    valid_user = User(authenticated=True, permissions=["access_core"], ip="192.168.1.1")
    timestamp = time.time()
    request_data = "core_access_request"
    request_hash = hashlib.sha256(f"{timestamp}{request_data}".encode()).hexdigest()

    print("\nTest 1: Valid User")
    try:
        result = access_core_system(valid_user, timestamp, request_data, request_hash)
        print(result)
    except SecurityError as e:
        print(f"Access Denied: {e}")

    # Invalid user (wrong IP)
    invalid_user = User(authenticated=True, permissions=["access_core"], ip="8.8.8.8")
    print("\nTest 2: Invalid IP (Triggers Attack Mode after failures)")
    for _ in range(state.max_attempts + 1):
        try:
            access_core_system(invalid_user, timestamp, request_data, request_hash)
        except SecurityError as e:
            print(f"Access Denied: {e}")

    # Post-attack mode test
    print("\nTest 3: Valid User After Attack Mode")
    try:
        result = access_core_system(valid_user, timestamp, request_data, request_hash)
        print(result)
    except SecurityError as e:
        print(f"Access Denied: {e}")

    # Reset state for further testing
    state.reset()

if __name__ == "__main__":
    test_chakravyuha()





