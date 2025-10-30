# Password Strength Checker

# Ask user to enter password
password = input("Enter your password to check its strength: ")

# Print the entered password
print("Your entered password is:", password)

# Initialize strength score
strength = 0

# Check length
if len(password) >= 6:
    strength += 1
if len(password) > 10:
    strength += 1

# Check for uppercase letters
if any(char.isupper() for char in password):
    strength += 1

# Check for lowercase letters
if any(char.islower() for char in password):
    strength += 1

# Check for numbers
if any(char.isdigit() for char in password):
    strength += 1

# Check for special characters
special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>/?"
if any(char in special_chars for char in password):
    strength += 1

# Evaluate strength
if strength <= 2:
    print("Password strength: Weak")
elif strength <= 4:
    print("Password strength: Medium")
else:
    print("Password strength: Strong")


