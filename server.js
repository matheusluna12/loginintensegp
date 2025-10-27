import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();
const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "segredo_troque_isto";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "1h";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5173";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

app.use(express.json());
app.use(cors({ origin: CORS_ORIGIN, credentials: false }));

const PASSWORD_HASH = bcrypt.hashSync("123456", 10);
const users = [
  { id: 1, nome: "Matheus", documento: "123456789", perfil: "aluno", password_hash: PASSWORD_HASH },
  { id: 2, nome: "Rafael", documento: "987654321", perfil: "professor", password_hash: PASSWORD_HASH },
  { id: 3, nome: "Bruno", documento: "1234567899", perfil: "diretor", password_hash: PASSWORD_HASH },
  { id: 4, nome: "Pai", documento: "11222333444", perfil: "pai", password_hash: PASSWORD_HASH }
];

function gerarToken(usuario) {
  const payload = { sub: usuario.id, documento: usuario.documento, perfil: usuario.perfil, nome: usuario.nome };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function autenticar(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ mensagem: "Token ausente" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.usuario = { id: payload.sub, nome: payload.nome, documento: payload.documento, perfil: payload.perfil };
    next();
  } catch {
    return res.status(401).json({ mensagem: "Token inválido ou expirado" });
  }
}

function exigirPerfis(...perfils) {
  return (req, res, next) => {
    if (!req.usuario?.perfil) return res.status(401).json({ mensagem: "Não autenticado" });
    if (!perfils.includes(req.usuario.perfil)) return res.status(403).json({ mensagem: "Acesso negado" });
    next();
  };
}

app.post("/auth/login", (req, res) => {
  const documento = (req.body?.documento ?? "").trim();
  const senha = (req.body?.senha ?? "").toString();
  if (!documento || !senha) return res.status(400).json({ mensagem: "Campos obrigatórios: documento e senha" });
  const usuario = users.find(u => u.documento === documento);
  if (!usuario) return res.status(401).json({ mensagem: "Credenciais inválidas" });
  const ok = bcrypt.compareSync(senha, usuario.password_hash);
  if (!ok) return res.status(401).json({ mensagem: "Credenciais inválidas" });
  const token = gerarToken(usuario);
  res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, documento: usuario.documento, perfil: usuario.perfil } });
});

app.get("/me", autenticar, (req, res) => res.json(req.usuario));
app.get("/area/aluno", autenticar, exigirPerfis("aluno"), (req, res) => res.json({ mensagem: `Bem-vindo(a), ${req.usuario.nome} (aluno)` }));
app.get("/area/professor", autenticar, exigirPerfis("professor"), (req, res) => res.json({ mensagem: `Bem-vindo(a), ${req.usuario.nome} (professor)` }));
app.get("/area/diretor", autenticar, exigirPerfis("diretor"), (req, res) => res.json({ mensagem: `Bem-vindo(a), ${req.usuario.nome} (diretor)` }));
app.get("/area/pai", autenticar, exigirPerfis("pai"), (req, res) => res.json({ mensagem: `Bem-vindo(a), ${req.usuario.nome} (pai)` }));

app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
