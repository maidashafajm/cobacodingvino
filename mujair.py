import streamlit as st
import re
import os
import time
from supabase import create_client, Client
from dotenv import load_dotenv



# Load environment variables
load_dotenv()

# Fungsi inisialisasi Supabase client
@st.cache_resource
def init_supabase() -> Client:
    """
    Inisialisasi koneksi ke Supabase
    """
    url = os.getenv("SUPABASE_URL") or st.secrets.get("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY") or st.secrets.get("SUPABASE_KEY")
    
    if not url or not key:
        st.error("SUPABASE_URL dan SUPABASE_KEY harus diset!")
        st.stop()
    
    return create_client(url, key)

# Fungsi validasi email
def validate_email(email: str) -> bool:
    """
    Validasi format email menggunakan regex
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Fungsi validasi password
def validate_password(password: str) -> tuple[bool, str]:
    """
    Validasi password harus mengandung:
    - Minimal 8 karakter
    - Huruf besar
    - Huruf kecil
    - Angka
    - Karakter khusus
    """
    if len(password) < 8:
        return False, "Password minimal 8 karakter"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password harus mengandung huruf besar"
    
    if not re.search(r'[a-z]', password):
        return False, "Password harus mengandung huruf kecil"
    
    if not re.search(r'[0-9]', password):
        return False, "Password harus mengandung angka"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password harus mengandung karakter khusus (!@#$%^&*...)"
    
    return True, "Password valid"

# Fungsi cek email sudah terdaftar atau belum
def check_email_exists(supabase: Client, email: str) -> bool:
    """
    Cek apakah email sudah terdaftar di database
    """
    try:
        response = supabase.table('users').select('email').eq('email', email).execute()
        return len(response.data) > 0
    except Exception as e:
        return False

# Fungsi handle verification dari URL
def handle_verification():
    """
    Handle verification callback dari email
    """
    # Ambil parameter dari URL
    query_params = st.query_params
    
    if "access_token" in query_params and "type" in query_params:
        token_type = query_params.get("type")
        access_token = query_params.get("access_token")
        
        supabase = init_supabase()
        
        try:
            # Set session dengan token
            supabase.auth.set_session(access_token, query_params.get("refresh_token", ""))
            
            if token_type == "signup":
                # Update user verification status
                user = supabase.auth.get_user()
                if user:
                    supabase.table('users').update({
                        "is_verified": True
                    }).eq('id', user.user.id).execute()
                
                st.success("✅ Email berhasil diverifikasi! Silakan login.")
                
            elif token_type == "recovery":
                # Redirect ke halaman reset password
                st.session_state.page = "reset_password"
                st.session_state.recovery_token = access_token
                st.rerun()
                
        except Exception as e:
            st.error(f"❌ Verifikasi gagal: {e}")

# Halaman Register
def register_page(supabase: Client, role: str):
    """
    Halaman registrasi pengguna baru
    """
    st.header(f"📝 Registrasi - {role.capitalize()}")
    
    with st.form("register_form"):
        email = st.text_input("Email", placeholder="nama@example.com")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Konfirmasi Password", type="password")
        
        submitted = st.form_submit_button("Daftar", use_container_width=True)
        
        if submitted:
            # Validasi email kosong
            if not email:
                st.error("Email tidak boleh kosong!")
                return
            
            # Validasi format email
            if not validate_email(email):
                st.error("Format email tidak valid!")
                return
            
            # Cek email sudah terdaftar
            if check_email_exists(supabase, email):
                st.error("Email sudah terdaftar! Silakan login atau gunakan email lain.")
                return
            
            # Validasi password kosong
            if not password:
                st.error("Password tidak boleh kosong!")
                return
            
            # Validasi kekuatan password
            is_valid, message = validate_password(password)
            if not is_valid:
                st.error(f"Password tidak valid: {message}")
                return
            
            # Validasi konfirmasi password
            if password != confirm_password:
                st.error("Password tidak cocok!")
                return
            
            try:
                # Register user dengan Supabase Auth
                response = supabase.auth.sign_up({
    "email": email,
    "password": password,
    "options": {
        "data": {
            "role": role
        },
        "email_redirect_to": "https://myapp.streamlit.app"
    }
})
                
                time.sleep(1)

                # Simpan data tambahan ke table users
                if response.user:
                    supabase.table('users').insert({
                        "id": response.user.id,
                        "email": email,
                        "role": role,
                        "is_verified": False
                    }).execute()
                
                st.success("✅ Registrasi berhasil!")
                st.info(f"📧 Email verifikasi telah dikirim ke {email}")
                st.warning("Silakan cek email Anda dan klik link verifikasi untuk mengaktifkan akun.")
                
            except Exception as e:
                st.error(f"❌ Registrasi gagal: {e}")

# Halaman Login
def login_page(supabase: Client, role: str):
    """
    Halaman login pengguna
    """
    st.header(f"🔐 Login - {role.capitalize()}")
    
    with st.form("login_form"):
        email = st.text_input("Email", placeholder="nama@example.com")
        password = st.text_input("Password", type="password")
        
        col1, col2 = st.columns([2, 1])
        with col1:
            submitted = st.form_submit_button("Login", use_container_width=True)
        with col2:
            forgot = st.form_submit_button("Lupa Password?", use_container_width=True)
        
        if submitted:
            # Validasi input kosong
            if not email or not password:
                st.error("Email dan password tidak boleh kosong!")
                return
            
            try:
                # Login dengan Supabase Auth
                response = supabase.auth.sign_in_with_password({
                    "email": email,
                    "password": password
                })
                
                # Cek role user
                user_data = supabase.table('users').select('*').eq('id', response.user.id).single().execute()
                
                if user_data.data['role'] != role:
                    st.error(f"❌ Login gagal! Anda terdaftar sebagai {user_data.data['role']}, bukan {role}")
                    supabase.auth.sign_out()
                    return
                
                # Cek apakah email sudah diverifikasi
                if not response.user.email_confirmed_at:
                    st.error("⚠️ Email Anda belum diverifikasi!")
                    st.warning("Silakan cek email dan klik link verifikasi terlebih dahulu.")
                    supabase.auth.sign_out()
                    return
                
                st.success(f"✅ Login berhasil! Selamat datang, {email}")
                st.session_state.user = response.user
                st.session_state.role = role
                st.session_state.logged_in = True
                st.rerun()
                
            except Exception as e:
                st.error(f"❌ Login gagal: Email atau password salah, atau akun belum diverifikasi.")
        
        if forgot:
            st.session_state.page = "forgot_password"
            st.rerun()

# Halaman Lupa Password
def forgot_password_page(supabase: Client):
    """
    Halaman lupa password
    """
    st.header("🔑 Lupa Password")

    with st.form("forgot_password_form"):
        email = st.text_input("Email", placeholder="nama@example.com")
        col1, col2 = st.columns([1,1])
        with col1:
            submitted = st.form_submit_button("Kirim Email Reset", use_container_width=True)
        with col2:
            back = st.form_submit_button("Kembali", use_container_width=True)
    
    if submitted:
        if not email:
            st.error("Email tidak boleh kosong!")
        elif not validate_email(email):
            st.error("Format email tidak valid!")
        else:
            try:
                supabase.auth.reset_password_for_email(
                    email,
                    {"redirect_to": "https://myapp.streamlit.app/reset_password"}
                )
                st.success(f"✅ Email reset password telah dikirim ke {email}")
                st.info("Silakan cek email dan klik link untuk mengubah password.")
            except Exception as e:
                st.error(f"❌ Gagal mengirim email: {e}")

    if back:
        st.session_state.page = "main"
        st.rerun()

# Halaman Reset Password
def reset_password_page(supabase: Client):
    """
    Halaman reset password setelah klik link di email
    """
    st.header("🔄 Reset Password")

    # Ambil token recovery dari URL
    query_params = st.experimental_get_query_params()
    token = query_params.get("access_token", [None])[0] or st.session_state.get("recovery_token")

    if token:
        st.session_state.recovery_token = token  # simpan di session
    else:
        st.error("❌ Token reset password tidak ditemukan!")
        return

    with st.form("reset_password_form"):
        new_password = st.text_input("Password Baru", type="password")
        confirm_password = st.text_input("Konfirmasi Password Baru", type="password")
        submitted = st.form_submit_button("Ubah Password", use_container_width=True)

    if submitted:
        if not new_password:
            st.error("Password tidak boleh kosong!")
        else:
            is_valid, message = validate_password(new_password)
            if not is_valid:
                st.error(f"Password tidak valid: {message}")
            elif new_password != confirm_password:
                st.error("Password tidak cocok!")
            else:
                try:
                    supabase.auth.update_user(
                        {"password": new_password},
                        st.session_state.recovery_token
                    )
                    st.success("✅ Password berhasil diubah!")
                    st.info("Silakan login dengan password baru Anda.")
                    del st.session_state.recovery_token
                    st.session_state.page = "main"
                except Exception as e:
                    st.error(f"❌ Gagal mengubah password: {e}")
                    
# Halaman Dashboard (setelah login)
def dashboard_page(user, role):
    """
    Halaman dashboard setelah login berhasil
    """
    st.header(f"🎯 Dashboard - {role.capitalize()}")
    
    st.success(f"Selamat datang, {user.email}!")
    
    st.info("🚧 Sistem akuntansi akan dibuat di bagian ini...")
    
    if st.button("Logout", type="primary"):
        supabase = init_supabase()
        supabase.auth.sign_out()
        st.session_state.clear()
        st.rerun()

# Main App
def main():
    """
    Aplikasi utama Tilapia Suite
    """
    # Page config
    st.set_page_config(
        page_title="Tilapia Suite",
        page_icon="🐟",
        layout="centered"
    )
    
    # Custom CSS
    st.markdown("""
    <style>
    .main-title {
        text-align: center;
        color: #1E88E5;
        font-size: 3em;
        font-weight: bold;
        margin-bottom: 0;
    }
    .subtitle {
        text-align: center;
        color: #666;
        font-size: 1.2em;
        margin-top: 0;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Title
    st.markdown('<p class="main-title">🐟 Tilapia Suite</p>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Sistem Akuntansi Budidaya Ikan Mujair</p>', unsafe_allow_html=True)
    st.divider()
    
    # Initialize Supabase
    supabase = init_supabase()
    
    # Handle verification callback
    handle_verification()
    
    # Initialize session state
    if 'page' not in st.session_state:
        st.session_state.page = 'main'
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    # Jika sudah login, tampilkan dashboard
    if st.session_state.logged_in and 'user' in st.session_state:
        dashboard_page(st.session_state.user, st.session_state.role)
        return
    
    # Jika halaman reset password
    if st.session_state.page == 'reset_password':
        reset_password_page(supabase)
        return
    
    # Jika halaman forgot password
    if st.session_state.page == 'forgot_password':
        forgot_password_page(supabase)
        return
    
    # Pilih Role
    if 'selected_role' not in st.session_state:
        st.subheader("👤 Pilih Role Anda")
        
        roles = ["akuntan", "owner", "karyawan", "kasir"]
        role_icons = {"akuntan": "💼", "owner": "👔", "karyawan": "👷", "kasir": "💰"}
        
        cols = st.columns(4)
        for i, role in enumerate(roles):
            with cols[i]:
                if st.button(f"{role_icons[role]}\n{role.capitalize()}", 
                           key=f"role_{role}", 
                           use_container_width=True):
                    st.session_state.selected_role = role
                    st.rerun()
    else:
        # Tampilkan role yang dipilih
        role = st.session_state.selected_role
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.info(f"Role dipilih: **{role.capitalize()}**")
            if st.button("Ganti Role", use_container_width=True):
                del st.session_state.selected_role
                st.rerun()
        
        st.divider()
        
        # Tab Login dan Register
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
        
        with tab1:
            login_page(supabase, role)
        
        with tab2:
            register_page(supabase, role)

if __name__ == "__main__":
    main()