import requests
from PIL import Image

# SEEDED VULN: Command injection via user input
def get_user_data(username):
    import os
    # Semgrep flags this — user input passed to os.system
    os.system("curl https://api.example.com/user/" + username)

# SEEDED VULN 2: SQL injection via string concatenation
def get_user_by_id(user_id, cursor):
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchall()

# SAFE Pillow usage — vulnerable Pillow methods not called
def resize_image(path):
    img = Image.open(path)
    img = img.resize((800, 600))
    return img
