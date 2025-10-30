import pyotp
import time
# You would typically store the user's secret key in a database after initial setup.
# For this example, we generate a random key once and use it.
# NOTE: This key must be a base32 string and should be unique for each user.
USER_SECRET_KEY = pyotp.random_base32() 

def check_knowledge_factor():
    """Simulates checking the 'Something You Know' (Password) factor."""
    print("\n--- FACTOR 1: KNOWLEDGE (Password) ---")
    
    # In a real application, you'd compare a hash of the entered password 
    # with the stored password hash.
    # For simulation, we'll use a fixed 'secret_password'.
    secret_password = "SecurePassword123" 
    
    entered_password = input("Enter password: ")
    
    if entered_password == secret_password:
        print("✅ Password check successful.")
        return True
    else:
        print("❌ Password incorrect.")
        return False

def check_possession_factor(user_secret_key):
    """
    Simulates checking the 'Something You Have' (TOTP Code) factor.
    
    :param user_secret_key: The user's unique base32 secret key for TOTP.
    :return: True if the TOTP code is valid, False otherwise.
    """
    print("\n--- FACTOR 2: POSSESSION (Authenticator Code) ---")
    
    # 1. Create a TOTP object using the user's secret key
    totp = pyotp.TOTP(user_secret_key)
    
    # For demonstration: print the current code the server expects. 
    # In a real app, this is kept secret on the server.
    # print(f"(DEBUG: Current server-expected TOTP: {totp.now()})")
    
    # 2. Get user input for the TOTP code
    entered_code = input("Enter the 6-digit TOTP code: ")
    
    # 3. Logic to validate the user's code against the current (and recent) TOTP
    # The 'verify' method checks the current time-step and optionally a window
    # around it to account for slight clock skew (valid_window=1 checks the code 
    # generated 30s ago, 'now', and 30s in the future).
    if totp.verify(entered_code, valid_window=1):
        print("✅ TOTP Code check successful.")
        return True
    else:
        print("❌ TOTP Code incorrect.")
        return False

# Part 2: 2FA Function
def two_factor_authentication(user_secret_key):
    """
    The main function to perform two-factor authentication.
    
    :param user_secret_key: The user's unique base32 secret key for TOTP.
    :return: True if both factors are successful, False otherwise.
    """
    print("\n--- Starting Two-Factor Authentication Process ---")
    
    # Step 1: Check the first factor (Knowledge)
    password_ok = check_knowledge_factor()

    # Only proceed to the second factor if the first was successful
    if password_ok:
        print("\nProceeding to second factor...")
        # Step 2: Check the second factor (Possession)
        totp_ok = check_possession_factor(user_secret_key)
        
        if totp_ok:
            print("\n🎉 2FA SUCCESSFUL! Access Granted.")
            return True
        else:
            print("\n🛑 2FA FAILED: Possession factor failed.")
            return False
    else:
        print("\n🛑 2FA FAILED: Knowledge factor failed.")
        return False

# --- Main execution block ---

# Setup: Generate QR Code URI for a user to scan with an authenticator app (like Google Authenticator)
# The user_id and app_name would typically be dynamic.
uri = pyotp.totp.TOTP(USER_SECRET_KEY).provisioning_uri(
    name='user@example.com', 
    issuer_name='SecureAppDemo'
)

# You would display this URI as a QR Code to the user for initial setup.
print("\n--- Initial Setup (Simulated) ---")
print("New User Secret Key (for their authenticator app):", USER_SECRET_KEY)
print(f"Provisioning URI (to generate QR Code): {uri}")
print("Please use an authenticator app (like Google Authenticator or Authy) to scan a QR Code generated from the URI above.")
print("The code will refresh every 30 seconds.")
print("-" * 40)


# Run the 2FA function
if __name__ == "__main__":
    # Wait a moment to allow the user to check their authenticator app after seeing the key/URI
    time.sleep(1) 
    
    authentication_result = two_factor_authentication(USER_SECRET_KEY)
    
    print("\nFinal Authentication Status:", "GRANTED" if authentication_result else "DENIED")