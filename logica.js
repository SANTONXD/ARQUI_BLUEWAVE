const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: '1234',
  resave: false,
  saveUninitialized: true,
}));

// Servir archivos estáticos desde carpeta "public"
app.use(express.static(path.join(__dirname, 'public')));

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'arqui'
});
const promisePool = pool.promise();

// Registro
app.post('/register', async (req, res) => {
  const { name, user, email, rol, password } = req.body;
  try {
    const [existing] = await promisePool.query('SELECT * FROM Usuarios WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(400).send('El correo ya se encuentra registrado');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await promisePool.query(
      'INSERT INTO Usuarios (nombre, apellido, email, password, rol) VALUES (?, ?, ?, ?, ?)',
      [name, user, email, hashedPassword, rol.toLowerCase()]
    );
    res.redirect('/index.html');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error en el registro');
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await promisePool.query('SELECT * FROM Usuarios WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).send('Usuario no encontrado');

    const userData = rows[0];
    const validPassword = await bcrypt.compare(password, userData.password);
    if (!validPassword) return res.status(401).send('Contraseña incorrecta');

    req.session.userId = userData.id_usuario;
    req.session.rol = userData.rol;
    res.redirect(`/principal.html?rol=${userData.rol}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error en el login');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).send('Error al cerrar sesión');
    res.redirect('/index.html');
  });
});

// Guardar evento
app.post('/evento', async (req, res) => {
  const { latitud, longitud, fecha, hora, descripcion } = req.body;
  const userId = req.session.userId;

  if (!userId) return res.status(401).send('No has iniciado sesión');

  try {
    await promisePool.query(
      'INSERT INTO Eventos (latitud, longitud, fecha, hora, descripcion, creado_por) VALUES (?, ?, ?, ?, ?, ?)',
      [latitud, longitud, fecha, hora, descripcion, userId]
    );
    res.status(200).send('Evento guardado');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al guardar el evento');
  }
});

// Obtener eventos
app.get('/eventos', async (req, res) => {
  try {
    const [rows] = await promisePool.query('SELECT * FROM Eventos');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al obtener eventos');
  }
});

// Servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});
