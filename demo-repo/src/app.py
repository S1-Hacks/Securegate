import subprocess
import requests
from PIL import Image


# FIXED: use subprocess with a list — no shell injection possible
def get_user_data(username):
    subprocess.run(["curl", "https://api.example.com/user/" + username], check=False)


# FIXED: parameterized query — no SQL injection
def get_user_by_id(user_id, cursor):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()


# SAFE Pillow usage — vulnerable Pillow methods not called
def resize_image(path):
    img = Image.open(path)
    img = img.resize((800, 600))
    return img
