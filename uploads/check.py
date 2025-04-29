from werkzeug.security import check_password_hash

# The stored hash (from the database)
stored_hash = 'scrypt:32768:8:1$Z7MNdmRlX2EOTiMw$fcdf4fb1716f533377bc86c96c346d75c48fa0e50c24c40a2c555cc55ee44556335f0f245bafa20a1f829ad799dbdf05d729de3058898fa28d11f3bea8221d84'

# The entered password
entered_password = 'Harshavardhan'  # user orignial password

# Check if the entered password matches the stored hash
print(check_password_hash(stored_hash, entered_password))  # return True if correct
