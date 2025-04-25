from werkzeug.security import check_password_hash

# The stored hash (from the database)
stored_hash = 'enter the hashed password from the query output'

# The entered password
entered_password = 'enter the original password'  # user orignial password
# Check if the entered password matches the stored hash
print(check_password_hash(stored_hash, entered_password))  # return True if correct
