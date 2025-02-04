import re
import tkinter as tk
import hashlib

# Function to check password strength
def check_password_strength(password):
    strength = 0
    
    # Length check: Should be at least 8 characters long
    if len(password) >= 8:
        strength += 1
        
    # Check if password contains both lowercase and uppercase letters
    if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
        strength += 1
        
    # Check if password contains digits
    if re.search(r'\d', password):
        strength += 1
        
    # Check if password contains special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength += 1
    
    # Check if password contains no spaces
    if not re.search(r'\s', password):
        strength += 1
        
    return strength  # Return strength level as a score out of 5

# Function to hash the password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to analyze password strength and display results
def analyze_password():
    password = entry.get()
    strength = check_password_strength(password)

    # Determine strength level
    if strength == 5:
        message = "Password is Very Strong!"
    elif strength == 4:
        message = "Password is Strong!"
    elif strength == 3:
        message = "Password is Medium!"
    elif strength == 2:
        message = "Password is Weak!"
    else:
        message = "Password is Very Weak!"
    
    # Update labels with results
    result_label.config(text=message)
    hashed_password_label.config(text=f"Hashed Password: {hash_password(password)}")

# Set up the main Tkinter window
window = tk.Tk()
window.title("Password Strength Analyzer")
window.geometry("400x250")

# Create UI elements
label = tk.Label(window, text="Enter your password:")
label.pack(pady=10)

entry = tk.Entry(window, show="*", width=25)
entry.pack(pady=5)

analyze_button = tk.Button(window, text="Analyze Password", command=analyze_password)
analyze_button.pack(pady=10)

result_label = tk.Label(window, text="", font=("Helvetica", 12))
result_label.pack(pady=10)

hashed_password_label = tk.Label(window, text="", font=("Helvetica", 10))
hashed_password_label.pack(pady=10)

# Run the Tkinter event loop
window.mainloop()

