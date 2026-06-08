cat > demo-repo/src/app.py << 'EOF'
import requests
from PIL import Image

# SEEDED VULN: Command injection via user input
def get_user_data(username):
    import os
    # Semgrep flags this — user input passed to os.system
    os.system("curl https://api.example.com/user/" + username)

# SAFE Pillow usage — vulnerable Pillow methods not called
def resize_image(path):
    img = Image.open(path)
    img = img.resize((800, 600))
    return img
EOF