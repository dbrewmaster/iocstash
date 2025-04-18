import csv
from faker import Faker
import random

fake = Faker()

num_users = 100000
output_file = "users.csv"

generated_emails = set()

with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
    fieldnames = ["username", "password", "email", "first_name", "last_name", "address"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for _ in range(num_users):
        username = fake.user_name() + str(random.randint(1000, 9999))
        password = "Password123"  
        
       
        email = fake.email()
        while email in generated_emails:
            email = fake.email()  
        generated_emails.add(email)
        
        first_name = fake.first_name()
        last_name = fake.last_name()
        address = fake.address().replace("\n", ", ")

        writer.writerow({
            "username": username,
            "password": password,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "address": address
        })

print(f"Generated {num_users} users and saved to {output_file}")
