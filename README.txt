
StegaCrypt - Multimedia Steganography and Security System

StegaCrypt is a browser-based multimedia steganography system developed using Python and Django. It supports encryption and hiding of text in image, audio, and video files, enhanced with morph code transformations and password protection.

Final Year Project | BCA | Ness Wadia College of Commerce | Savitribai Phule Pune University
Developed by: Mohd Taha Zakir Shaikh

------------------------------------------------------------
FEATURES:

- Image Steganography using LSB technique (.png)
- Audio Steganography in .wav format
- Video Steganography (text hidden in first frame of .mp4/.avi)
- Morph Encoder (Binary, Hex, Base64, Reverse, Morse Code)
- Password protection on all encryption modules
- Simple hardcoded login system
- Background video integration and Bootstrap-based UI

------------------------------------------------------------
SETUP INSTRUCTIONS:

Requirements:
- Python 3.10.x
- pip
- Git (optional)

Steps:
1. Clone the repository:
   git clone https://github.com/ShaikhTaha4/StegaCrypt.git
   cd StegaCrypt/stegano_project

2. Create and activate a virtual environment:
   python -m venv venv
   venv\Scripts\activate    (for Windows)

3. Install required dependencies:
   pip install -r requirements.txt

4. Run the Django server:
   python manage.py runserver

5. Open your browser and go to:
   http://127.0.0.1:8000/

------------------------------------------------------------
LOGIN CREDENTIALS (HARDCODED):

Username       | Password
-------------- | --------------
admin          | adminpass
user1          | password123
guest          | guest123

------------------------------------------------------------
PROJECT STRUCTURE:

stegano_project/
├── manage.py
├── requirements.txt
├── static/
├── templates/
├── encrypted content/
└── stegano_app/
    ├── views.py
    ├── urls.py
    └── ...

------------------------------------------------------------
FUTURE ENHANCEMENTS:

- Role-based dynamic login
- Responsive mobile layout
- AI-driven steganalysis support
- Admin interface with project logs and analytics

------------------------------------------------------------
LICENSE:

This project is for educational and academic demonstration only.
Commercial use or resale requires explicit permission.

------------------------------------------------------------
CONTACT:

GitHub: ShaikhTaha4
Email: shaikhmohammadtaha4@gmail.com
LinkedIn: https://tinyurl.com/taha4
