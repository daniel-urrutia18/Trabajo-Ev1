import express from "express";
import { randomBytes, scrypt } from "node:crypto";
import { promisify } from "node:util";
import { v4 as uuidv4 } from "uuid";

const PORT = process.env.PORT ?? 3000;
const scryptAsync = promisify(scrypt);

const app = express();
app.use(express.json());

// Almacenamiento en memoria
const users = [
  {
    username: "admin",
    name: "Gustavo Alfredo Marín Sáez",
    password:
      "1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01", // certamen123
  },
];

const reminders = [];

// Middleware de autorización
const authMiddleware = (req, res, next) => {
  const token = req.header("X-Authorization");
  if (!token) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  const user = users.find((u) => u.token === token);
  if (!user) {
    return res.status(401).json({ error: "Token inválido" });
  }

  req.user = user;
  next();
};

// Función para validar recordatorio
const validateReminder = (content, important) => {
  if (typeof content !== "string" || content.trim().length === 0 || content.length > 120) {
    return false;
  }
  if (important !== undefined && typeof important !== "boolean") {
    return false;
  }
  return true;
};

// Login
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username y password son requeridos" });
  }

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: "Usuario no existe" });
  }

  const [salt, storedKey] = user.password.split(":");
  const key = (await scryptAsync(password, salt, 64)).toString("hex");

  if (key !== storedKey) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }

  // Generar token
  const token = randomBytes(48).toString("hex");
  user.token = token;

  res.json({
    username: user.username,
    name: user.name,
    token: user.token,
  });
});

// Listar recordatorios
app.get("/api/reminders", authMiddleware, (req, res) => {
  const sortedReminders = [...reminders].sort((a, b) => {
    if (a.important === b.important) {
      return b.createdAt - a.createdAt;
    }
    return b.important - a.important;
  });

  res.json(sortedReminders);
});

// Crear recordatorio
app.post("/api/reminders", authMiddleware, (req, res) => {
  const { content, important = false } = req.body;

  if (!validateReminder(content, important)) {
    return res.status(400).json({ error: "Datos inválidos" });
  }

  const reminder = {
    id: uuidv4(),
    content,
    createdAt: Date.now(),
    important,
  };

  reminders.push(reminder);
  res.status(201).json(reminder);
});

// Actualizar recordatorio
app.patch("/api/reminders/:id", authMiddleware, (req, res) => {
  const { id } = req.params;
  const { content, important } = req.body;

  if (content !== undefined || important !== undefined) {
    if (!validateReminder(content, important)) {
      return res.status(400).json({ error: "Datos inválidos" });
    }
  }

  const index = reminders.findIndex((r) => r.id === id);
  if (index === -1) {
    return res.status(404).json({ error: "Recordatorio no encontrado" });
  }

  const updatedReminder = {
    ...reminders[index],
    content: content ?? reminders[index].content,
    important: important ?? reminders[index].important,
  };

  reminders[index] = updatedReminder;
  res.json(updatedReminder);
});

// Borrar recordatorio
app.delete("/api/reminders/:id", authMiddleware, (req, res) => {
  const { id } = req.params;
  const index = reminders.findIndex((r) => r.id === id);

  if (index === -1) {
    return res.status(404).json({ error: "Recordatorio no encontrado" });
  }

  reminders.splice(index, 1);
  res.status(204).send();
});

app.use(express.static("public"));

app.listen(PORT, (error) => {
  if (error) {
    console.error(`No se puede ocupar el puerto ${PORT} :(`);
    return;
  }

  console.log(`Escuchando en el puerto ${PORT}`);
});
