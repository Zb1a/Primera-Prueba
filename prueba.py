import http.server
import socketserver
import base64

PORT = 8000

# Credenciales de acceso (usuario: contraseña)
valid_username = "admin"
valid_password = "password123"

# Función para verificar si las credenciales son correctas
def check_credentials(auth_header):
    if auth_header:
        # Decodificar el encabezado de autenticación
        auth_type, auth_credentials = auth_header.split(' ', 1)
        if auth_type.lower() == "basic":
            decoded_credentials = base64.b64decode(auth_credentials).decode('utf-8')
            username, password = decoded_credentials.split(":", 1)
            if username == valid_username and password == valid_password:
                return True
    return False

class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Obtener las cabeceras de la solicitud
        auth_header = self.headers.get('Authorization')

        # Si no está autenticado, pedir las credenciales
        if not check_credentials(auth_header):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Login"')
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Acceso denegado. Por favor, ingresa tus credenciales.')
            return

        # Obtener la dirección IP del cliente
        client_ip = self.client_address[0]
        print(f"Conexión desde IP: {client_ip}")

        # Redirigir a Instagram si está autenticado
        self.send_response(302)
        self.send_header("Location", "https://www.instagram.com/")
        self.end_headers()

# Iniciar el servidor
with socketserver.TCPServer(("", PORT), LoggingHandler) as httpd:
    print(f"Servidor corriendo en http://127.0.0.1:{PORT}")
    httpd.serve_forever()
