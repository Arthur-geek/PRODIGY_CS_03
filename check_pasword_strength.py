import re

def check_password_strength(password):
    """
    Checks the strength of a password based on length, presence of uppercase and lowercase letters,
    numbers, and special characters. Provides feedback on the password's strength.

    Parameters:
    - password (str): The password to be assessed.

    Returns:
    - str: A message indicating the password strength.
    """
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    digit_criteria = bool(re.search(r'\d', password))
    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

    score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_char_criteria])

    strength_levels = {
        5: "Very Strong",
        4: "Strong",
        3: "Moderate",
        2: "Weak",
        1: "Very Weak",
        0: "Extremely Weak"
    }

    feedback = {
        "At least 8 characters long": length_criteria,
        "Contains an uppercase letter": uppercase_criteria,
        "Contains a lowercase letter": lowercase_criteria,
        "Contains a digit": digit_criteria,
        "Contains a special character": special_char_criteria
    }

    missing_criteria = [desc for desc, met in feedback.items() if not met]
    feedback_message = " and ".join(missing_criteria) if missing_criteria else "Meets all criteria"

    return strength_levels[score], feedback_message

def main():
    """
    Main function to interact with the user for password strength checking.

    Parameters:
    - None

    Returns:
    - None
    """
    print("Welcome to the Password Complexity Checker")

    while True:
        password = input("Enter a password to check its strength: ")
        strength, feedback = check_password_strength(password)
        print(f"Password Strength: {strength}")
        print(f"Feedback: {feedback}")

        another = input("Do you want to check another password? (yes/no): ").lower()
        if another != 'yes':
            break

    print("Thank you for using the Password Complexity Checker. Goodbye!")

if __name__ == "__main__":
    main()
