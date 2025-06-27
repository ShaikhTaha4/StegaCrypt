from django.contrib import admin
from django.urls import path
from stegano_app import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # Set Login as Default Page
    path('', views.login_view, name='login'),
    path('index/', views.index, name='index'),

    # Login System
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),


    # Image Steganography
    path('image_steganography/', views.image_steganography_selection, name='image_steganography'),
    path('encryption/', views.encryption_view, name='encryption'),
    path('decryption/', views.decryption_view, name='decryption'),

    # Audio Steganography
    path('audio_steganography/', views.audio_steganography_selection, name='audio_steganography'),
    path('audio_encrypt/', views.audio_encrypt, name='audio_encrypt'),
    path('audio_decrypt/', views.audio_decrypt, name='audio_decrypt'),

    # Video Steganography (Text)
    path('video_steganography/', views.video_steganography_selection, name='video_steganography'),
    path('video_text_encrypt/', views.video_text_encrypt, name='video_text_encrypt'),
    path('video_text_decrypt/', views.video_text_decrypt, name='video_text_decrypt'),

    # Morph Code Steganography
    path('morph_code/', views.morph_code_selection, name='morph_code_selection'),
    path('morph_encode/', views.morph_encode, name='morph_encode'),
    path('morph_decode/', views.morph_decode, name='morph_decode'),
]

# ✅ Serve media files in development
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
