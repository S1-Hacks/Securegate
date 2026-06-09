import subprocess
import requests
from PIL import Image


def get_user_data(username):
    subprocess.run(
        ["curl", "https://api.example.com/user/" + username],
        check=True,
    )


def get_user_by_id(user_id, cursor):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchall()


def resize_image(path):
    img = Image.open(path)
    img = img.resize((800, 600))
    return img
