import csv
import aiohttp
import asyncio

API_URL = "http://127.0.0.1:8080/register"
input_file = "users.csv"
failed_file = "failed_users.csv"
total_users = 100000  

async def register_user(session, row, writer, progress_counter):
    data = {
        "username": row["username"],
        "password": row["password"],
        "email": row["email"],
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "address": row["address"]
    }

    try:
        async with session.post(API_URL, data=data) as response:
            if response.status == 200:
                progress_counter[0] += 1  
                progress = (progress_counter[0] / total_users) * 100
                print(f"Registered: {row['username']} - {progress_counter[0]}/{total_users} ({progress:.2f}%)")
            else:
                error_message = await response.text()
                print(f"Failed to register: {row['username']} - {error_message.strip()}")
                row["error_message"] = error_message.strip()
                writer.writerow(row)  # Save to failed_users.csv
    except Exception as e:
        print(f"Error registering {row['username']}: {str(e)}")
        row["error_message"] = str(e)
        writer.writerow(row)  # Save to failed_users.csv

async def main():
    with open(input_file, "r", encoding="utf-8") as csvfile, open(failed_file, "w", encoding="utf-8", newline="") as failfile:
        reader = csv.DictReader(csvfile)
        fieldnames = reader.fieldnames + ["error_message"]
        writer = csv.DictWriter(failfile, fieldnames=fieldnames)
        
        writer.writeheader()  # Write the header to the failed file

        async with aiohttp.ClientSession() as session:
            tasks = []
            progress_counter = [0]  
            
            for i, row in enumerate(reader):
                task = register_user(session, row, writer, progress_counter)
                tasks.append(task)
                
                if len(tasks) >= 100:  
                    await asyncio.gather(*tasks)
                    tasks.clear()

            if tasks:
                await asyncio.gather(*tasks)

asyncio.run(main())

