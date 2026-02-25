import express from "express";
import mongoose, { Schema } from "mongoose";
import helmet from "helmet";
import cors from "cors";
import compression from "compression";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import session from "express-session";
import MongoStore from "connect-mongo";
import bcrypt from "bcrypt";
import crypto from "crypto";

const PORT = process.env.PORT || 4000;
const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb+srv://2smarthrm_db_user:YmGVf9tM7lf02qw1@cluster0.pqpzxty.mongodb.net/";
const SESSION_SECRET =
  process.env.SESSION_SECRET || "CHANGE_ME__SESSION_SECRET__VERY_LONG_RANDOM";

const COOKIE_NAME = process.env.COOKIE_NAME || "ex_sid";
const PRODUCTION = process.env.NODE_ENV === "production";
const IS_VERCEL = !!process.env.VERCEL;

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  : [
      "http://localhost:5173",
      "http://localhost:5175",
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:5174",
      "https://technicalsupportfeedbacks.exportech.com.pt",
    ];

const MASTER_EMAIL =
  process.env.MASTER_EMAIL || "paulo.ferreira@exportech.com.pt";
const MASTER_PASSWORD = process.env.MASTER_PASSWORD || "Admin12345!";

 
const runtimeState = {
  startedAt: new Date().toISOString(),
  lastError: null,
  lastDbError: null,
  sessionStore: "unknown",
};

function rememberError(where, err) {
  const payload = {
    at: new Date().toISOString(),
    where,
    name: err?.name || "Error",
    message: String(err?.message || err || "Unknown error"),
    code: err?.code ?? err?.status ?? null,
  };
  runtimeState.lastError = payload;
  if (String(where || "").toLowerCase().includes("mongo"))
    runtimeState.lastDbError = payload;

  console.error(`[${where}]`, err && err.stack ? err.stack : err);
}

function isCiphertextParseError(err) {
  const msg = String(err?.message || "");
  return msg.includes("Unable to parse ciphertext object");
}

 
mongoose.set("bufferCommands", false);

let mongoConnPromise = null;

async function connectMongo() {
  if (mongoose.connection.readyState === 1) return mongoose.connection;
  if (mongoConnPromise) return mongoConnPromise;

  mongoConnPromise = (async () => {
    try {
      const dbName = process.env.MONGO_DBNAME || undefined;
      await mongoose.connect(MONGO_URI, {
        dbName,
        serverSelectionTimeoutMS: 8000,
        connectTimeoutMS: 8000,
        socketTimeoutMS: 20000,
        retryWrites: true,
      });
      console.log("[mongo] connected");
      return mongoose.connection;
    } catch (e) {
      rememberError("mongo.connect", e);
      throw e;
    } finally {
      if (mongoose.connection.readyState !== 1) mongoConnPromise = null;
    }
  })();

  return mongoConnPromise;
}

function requireDb(req, res, next) {
  connectMongo()
    .then(() => next())
    .catch((e) => {
      return res.status(503).json({
        ok: false,
        error: "DB indisponível",
        type: e?.name || "MongoError",
        message: String(e?.message || e),
      });
    });
}

 
const app = express();
app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: false }));

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

app.use(morgan("combined"));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(compression());

 
function buildSessionStore() {
  try {
    const store = MongoStore.create({
      mongoUrl: MONGO_URI,
      collectionName: "exportech_sessions",
      ttl: 60 * 60 * 8,
      touchAfter: 60 * 10, 
    });

 
    store.on("error", (e) => rememberError("session.store.error", e));

    runtimeState.sessionStore = "mongo";
    return store;
  } catch (e) {
    rememberError("session.store.mongo_create", e);
    runtimeState.sessionStore = "memory";
    return undefined; // fallback MemoryStore
  }
}

app.use(
  session({
    name: COOKIE_NAME,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: buildSessionStore(),
    cookie: {
      httpOnly: true,
      sameSite: PRODUCTION ? "none" : "lax",
      secure: PRODUCTION,
      maxAge: 1000 * 60 * 60 * 8 * 5,
      path: "/",
    },
    rolling: true,
  })
);

 
app.use((err, req, res, next) => {
  if (!isCiphertextParseError(err)) return next(err);

  rememberError(`session.ciphertext_parse:${req.method} ${req.originalUrl}`, err); 
  res.clearCookie(COOKIE_NAME, { path: "/" }); 
  if (req.path === "/api/exportech/auth/status") {
    return res.status(200).json({
      ok: true,
      data: { authenticated: false, sessionCorrupted: true },
    });
  }
 
  return res.status(401).json({
    ok: false,
    error: "Sessão inválida (reinicia login)",
    type: "SessionCiphertextParseError",
  });
});

 
const ok = (res, data, code = 200) => res.status(code).json({ ok: true, data });
const errJson = (res, message = "Erro", code = 400, issues = null) =>{
  console.log("LOG DATA = ", message);
  res.status(code).json({ ok: false, error: message, issues });
}

const asyncH =
  (fn) =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch((e) => {
      rememberError(`route:${req.method} ${req.originalUrl}`, e);
      next(e);
    });

const limiterStrict = rateLimit({ windowMs: 10 * 60 * 1000, max: 900 });
const limiterAuth = rateLimit({ windowMs: 10 * 60 * 1000, max: 600 });
const limiterLogin = rateLimit({ windowMs: 15 * 60 * 1000, max: 80 });
const limiterPublicPost = rateLimit({ windowMs: 5 * 60 * 1000, max: 250 });

const requireAuth =
  (roles = []) =>
  (req, res, next) => {
    const u = req.session?.user;
    if (!u) return errJson(res, "Não autenticado", 401);
    if (roles.length && !roles.includes(u.role))
      return errJson(res, "Sem permissões", 403);
    next();
  };

const normalizeEmail = (v) => String(v || "").trim().toLowerCase();
const safeStr = (v) => String(v || "").replace(/\s+/g, " ").trim();
const makeToken = () => crypto.randomBytes(24).toString("hex");

 
const ExportechUserSchema = new Schema(
  {
    ex_name: { type: String, required: true },
    ex_email: { type: String, required: true, unique: true, index: true },
    ex_password_hash: { type: String, required: true },
    ex_role: {
      type: String,
      enum: ["master", "technician"],
      required: true,
      index: true,
    },
    ex_technician_id: {
      type: Schema.Types.ObjectId,
      ref: "ExportechTechnician",
      default: null,
      index: true,
    },
    ex_active: { type: Boolean, default: true, index: true },
    ex_created_at: { type: Date, default: Date.now },
  },
  { collection: "exportech_users" }
);

const ExportechTechnicianSchema = new Schema(
  {
    ex_name: { type: String, required: true },
    ex_role_title: { type: String, default: "Técnico" },
    ex_picture: { type: String, default: "" },
    ex_active: { type: Boolean, default: true, index: true },
    ex_public_token: { type: String, unique: true, index: true },
    ex_created_at: { type: Date, default: Date.now },
    ex_updated_at: { type: Date, default: Date.now },
  },
  { collection: "exportech_technicians" }
);

ExportechTechnicianSchema.pre("save", function (next) {
  this.ex_name = safeStr(this.ex_name);
  this.ex_role_title = safeStr(this.ex_role_title || "Técnico");
  if (!this.ex_public_token) this.ex_public_token = makeToken();
  this.ex_updated_at = new Date();
  next();
});

const ExportechFormSchema = new Schema(
  {
    ex_token: { type: String, required: true, unique: true, index: true },
    ex_tech: {
      type: Schema.Types.ObjectId,
      ref: "ExportechTechnician",
      required: true,
      index: true,
    },
    ex_tech_name_snapshot: { type: String, required: true },
    ex_created_at: { type: Date, default: Date.now, index: true },
    ex_used_at: { type: Date, default: null, index: true },
    ex_used_submission: {
      type: Schema.Types.ObjectId,
      ref: "ExportechSubmission",
      default: null,
    },
  },
  { collection: "exportech_forms" }
);
ExportechFormSchema.index({ ex_tech: 1, ex_created_at: -1 });

const ExportechSubmissionSchema = new Schema(
  {
    ex_tech: {
      type: Schema.Types.ObjectId,
      ref: "ExportechTechnician",
      required: true,
      index: true,
    },
    ex_tech_name_snapshot: { type: String, required: true },
    ex_empresa: { type: String, required: true },
    ex_cliente: { type: String, required: true },
    ex_data_ass: { type: String, required: true },
    ex_r1: { type: Number, required: true },
    ex_r2: { type: Number, required: true },
    ex_r3: { type: Number, required: true },
    ex_r4: { type: Number, required: true },
    ex_r5: { type: Number, required: true },
    ex_nps: { type: Number, default: null },
    ex_comentario: { type: String, default: "" },
    ex_created_at: { type: Date, default: Date.now },
  },
  { collection: "exportech_submissions" }
);
ExportechSubmissionSchema.index({ ex_created_at: -1 });

const ExportechAuditSchema = new Schema(
  {
    ex_actor: { type: String },
    ex_action: { type: String, required: true },
    ex_details: { type: Schema.Types.Mixed },
    ex_ip: { type: String },
    ex_at: { type: Date, default: Date.now },
  },
  { collection: "exportech_audit" }
);

const ExportechUser = mongoose.model("ExportechUser", ExportechUserSchema);
const ExportechTechnician = mongoose.model(
  "ExportechTechnician",
  ExportechTechnicianSchema
);
const ExportechForm = mongoose.model("ExportechForm", ExportechFormSchema);
const ExportechSubmission = mongoose.model(
  "ExportechSubmission",
  ExportechSubmissionSchema
);
const ExportechAudit = mongoose.model("ExportechAudit", ExportechAuditSchema);

const audit =
  (action) =>
  (req, res, next) => {
    res.on("finish", () => {
      ExportechAudit.create({
        ex_actor: req.session?.user?.email || "public",
        ex_action: action,
        ex_details: {
          method: req.method,
          path: req.originalUrl,
          status: res.statusCode,
        },
        ex_ip: req.ip,
      }).catch((e) => rememberError("mongo.audit.create", e));
    });
    next();
  };

async function ensureMasterUser() {
  const email = normalizeEmail(MASTER_EMAIL);
  const exists = await ExportechUser.findOne({ ex_email: email }).lean();
  if (exists) return;

  const hash = await bcrypt.hash(String(MASTER_PASSWORD), 12);
  await ExportechUser.create({
    ex_name: "Master",
    ex_email: email,
    ex_password_hash: hash,
    ex_role: "master",
    ex_active: true,
  });

  console.log(`[exportech] Master criado: ${email} / ${MASTER_PASSWORD}`);
}

async function bootstrapIfStandalone() {
  try {
    await connectMongo();
    await ensureMasterUser();

    if (!IS_VERCEL) {
      app.listen(PORT, () => console.log(`[server] http://localhost:${PORT}`));
    }
  } catch (e) {
    rememberError("bootstrap", e);

    if (!IS_VERCEL) {
      console.error(
        "[bootstrap] DB com erro. Server continua, rotas com DB vão dar 503."
      );
      app.listen(PORT, () =>
        console.log(`[server] http://localhost:${PORT} (DB com erro)`)
      );
    }
  }
}
bootstrapIfStandalone();

 
app.get("/", (_req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStateText =
    dbState === 1
      ? "connected"
      : dbState === 2
      ? "connecting"
      : dbState === 3
      ? "disconnecting"
      : "disconnected";

  res.json({
    ok: true,
    status: "Nice job !",
    env: { production: PRODUCTION, vercel: IS_VERCEL, nodeEnv: process.env.NODE_ENV || "undefined" },
    db: { state: dbStateText, readyState: dbState, lastDbError: runtimeState.lastDbError },
    session: { store: runtimeState.sessionStore, cookieName: COOKIE_NAME },
    lastError: runtimeState.lastError,
    startedAt: runtimeState.startedAt,
  });
});

app.get("/api/exportech/health", (_req, res) => {
  const s = mongoose.connection.readyState;
  res.json({
    ok: true,
    dbReadyState: s,
    dbConnected: s === 1,
    lastDbError: runtimeState.lastDbError,
    sessionStore: runtimeState.sessionStore,
  });
});

app.post(
  "/api/exportech/auth/login",
  limiterLogin,
  requireDb,
  audit("auth.login"),
  asyncH(async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!email || !email.includes("@")) return errJson(res, "Email inválido", 422);
    if (!password || password.length < 6) return errJson(res, "Password inválida", 422);

    const user = await ExportechUser.findOne({ ex_email: email, ex_active: true });
    if (!user) return errJson(res, "Credenciais inválidas", 401);

    const passOk = await bcrypt.compare(password, user.ex_password_hash);
    if (!passOk) return errJson(res, "Credenciais inválidas", 401);

    req.session.regenerate((err) => {
      if (err) return errJson(res, "Erro de sessão", 500);

      req.session.user = {
        id: String(user._id),
        email: user.ex_email,
        role: user.ex_role,
        name: user.ex_name,
        technicianId: user.ex_technician_id ? String(user.ex_technician_id) : null,
      };

      req.session.save((err2) => {
        if (err2) return errJson(res, "Erro de sessão", 500);
        ok(res, { authenticated: true, user: req.session.user });
      });
    });
  })
);

app.post(
  "/api/exportech/auth/logout",
  limiterAuth,
  audit("auth.logout"),
  asyncH(async (req, res) => {
    req.session.destroy(() => {
      res.clearCookie(COOKIE_NAME, { path: "/" });
      ok(res, { authenticated: false });
    });
  })
);

app.get(
  "/api/exportech/auth/status",
  limiterStrict,
  asyncH(async (req, res) => {
    if (!req.session?.user) return ok(res, { authenticated: false });
    ok(res, { authenticated: true, user: req.session.user });
  })
);

 
app.use((err, req, res, _next) => {
  const status = err?.status || err?.code || 500;
  if (res.headersSent) return;
 
  if (isCiphertextParseError(err)) {
    rememberError(`global_ciphertext:${req.method} ${req.originalUrl}`, err);
    res.clearCookie(COOKIE_NAME, { path: "/" });
    return res.status(200).json({ ok: true, data: { authenticated: false, sessionCorrupted: true } });
  }

  rememberError(`global_error:${req.method} ${req.originalUrl}`, err);

  res.status(status >= 400 && status <= 599 ? status : 500).json({
    ok: false,
    error: "Erro interno",
    type: err?.name || "Error",
    message: String(err?.message || err || "Unknown error"),
  });
});
 

app.post(
  "/api/exportech/auth/login",
  limiterLogin,
  audit("auth.login"),
  asyncH(async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!email || !email.includes("@")) return errJson(res, "Email inválido", 422);
    if (!password || password.length < 6) return errJson(res, "Password inválida", 422);

    const user = await ExportechUser.findOne({ ex_email: email, ex_active: true });
    if (!user) return errJson(res, "Credenciais inválidas", 401);

    const passOk = await bcrypt.compare(password, user.ex_password_hash);
    if (!passOk) return errJson(res, "Credenciais inválidas", 401);

    req.session.regenerate((err) => {
      if (err) return errJson(res, "Erro de sessão", 500);

      req.session.user = {
        id: String(user._id),
        email: user.ex_email,
        role: user.ex_role,
        name: user.ex_name,
        technicianId: user.ex_technician_id ? String(user.ex_technician_id) : null,
      };

      req.session.save((err2) => {
        if (err2) return errJson(res, "Erro de sessão", 500);
        ok(res, { authenticated: true, user: req.session.user });
      });
    });
  })
);

app.post(
  "/api/exportech/auth/logout",
  limiterAuth,
  audit("auth.logout"),
  asyncH(async (req, res) => {
    req.session.destroy(() => {
      res.clearCookie(COOKIE_NAME);
      ok(res, { authenticated: false });
    });
  })
);

app.get(
  "/api/exportech/auth/status",
  limiterStrict,
  asyncH(async (req, res) => {
    if (!req.session?.user) return ok(res, { authenticated: false });
    ok(res, { authenticated: true, user: req.session.user });
  })
);

app.get(
  "/api/exportech/technicians",
  limiterStrict,
  requireAuth(["master"]),
  audit("technicians.list"),
  asyncH(async (_req, res) => {
    const techs = await ExportechTechnician.find({ ex_active: true })
      .sort({ ex_created_at: 1 })
      .lean();

    const out = techs.map((t) => ({
      id: String(t._id),
      name: t.ex_name,
      role: t.ex_role_title,
      picture: t.ex_picture,
      publicToken: t.ex_public_token,
      active: t.ex_active,
      createdAt: t.ex_created_at,
    }));

    ok(res, out);
  })
);

app.get(
  "/api/exportech/technicians/me",
  limiterStrict,
  requireAuth(["master", "technician"]),
  audit("technicians.me"),
  asyncH(async (req, res) => {
    const u = req.session.user;
    if (u.role === "master") return ok(res, null);

    if (!u.technicianId) return errJson(res, "Conta de técnico sem technicianId", 500);
    const t = await ExportechTechnician.findById(u.technicianId).lean();
    if (!t) return errJson(res, "Técnico não encontrado", 404);

    ok(res, {
      id: String(t._id),
      name: t.ex_name,
      role: t.ex_role_title,
      picture: t.ex_picture,
      publicToken: t.ex_public_token,
    });
  })
);

app.post(
  "/api/exportech/technicians",
  limiterAuth,
  requireAuth(["master"]),
  audit("technicians.create"),
  asyncH(async (req, res) => {
    const name = safeStr(req.body?.name);
    const roleTitle = safeStr(req.body?.role || "Técnico");
    const picture = String(req.body?.picture || "").trim();

    const loginEmail = normalizeEmail(req.body?.loginEmail);
    const loginPassword = String(req.body?.loginPassword || "");

    if (!name) return errJson(res, "Nome obrigatório", 422);
    if (!loginEmail || !loginEmail.includes("@")) return errJson(res, "loginEmail inválido", 422);
    if (!loginPassword || loginPassword.length < 6) return errJson(res, "loginPassword inválida", 422);

    const emailTaken = await ExportechUser.findOne({ ex_email: loginEmail }).lean();
    if (emailTaken) return errJson(res, "Email já existe", 409);

    const tech = await ExportechTechnician.create({
      ex_name: name,
      ex_role_title: roleTitle,
      ex_picture: picture,
      ex_active: true,
    });

    const hash = await bcrypt.hash(loginPassword, 12);
    await ExportechUser.create({
      ex_name: name,
      ex_email: loginEmail,
      ex_password_hash: hash,
      ex_role: "technician",
      ex_technician_id: tech._id,
      ex_active: true,
    });

    ok(
      res,
      {
        id: String(tech._id),
        name: tech.ex_name,
        role: tech.ex_role_title,
        picture: tech.ex_picture,
        publicToken: tech.ex_public_token,
      },
      201
    );
  })
);

app.put(
  "/api/exportech/technicians/:id",
  limiterAuth,
  requireAuth(["master"]),
  audit("technicians.update"),
  asyncH(async (req, res) => {
    const id = String(req.params?.id || "");
    if (!mongoose.isValidObjectId(id)) return errJson(res, "id inválido", 422);

    const tech = await ExportechTechnician.findById(id);
    if (!tech) return errJson(res, "Técnico não encontrado", 404);

    if (req.body?.name !== undefined) tech.ex_name = safeStr(req.body.name);
    if (req.body?.role !== undefined) tech.ex_role_title = safeStr(req.body.role);
    if (req.body?.picture !== undefined) tech.ex_picture = String(req.body.picture || "").trim();
    if (req.body?.active !== undefined) tech.ex_active = !!req.body.active;

    await tech.save();

    ok(res, {
      id: String(tech._id),
      name: tech.ex_name,
      role: tech.ex_role_title,
      picture: tech.ex_picture,
      publicToken: tech.ex_public_token,
      active: tech.ex_active,
    });
  })
);

app.delete(
  "/api/exportech/technicians/:id",
  limiterAuth,
  requireAuth(["master"]),
  audit("technicians.delete"),
  asyncH(async (req, res) => {
    const id = String(req.params?.id || "");
    if (!mongoose.isValidObjectId(id)) return errJson(res, "id inválido", 422);

    const tech = await ExportechTechnician.findById(id);
    if (!tech) return errJson(res, "Técnico não encontrado", 404);

    tech.ex_active = false;
    await tech.save();

    ok(res, { deleted: true });
  })
);

app.post(
  "/api/exportech/forms",
  limiterAuth,
  requireAuth(["technician", "master"]),
  audit("forms.create"),
  asyncH(async (req, res) => {
    const u = req.session.user;
    if (!u.technicianId) return errJson(res, "Conta de usúario sem técnico associado !", 500);

    const tech = await ExportechTechnician.findById(u.technicianId).lean();
    if (!tech || !tech.ex_active) return errJson(res, "Técnico não encontrado !", 404);

    const token = makeToken();

    const created = await ExportechForm.create({
      ex_token: token,
      ex_tech: tech._id,
      ex_tech_name_snapshot: tech.ex_name,
      ex_created_at: new Date(),
      ex_used_at: null,
      ex_used_submission: null,
    });

    ok(
      res,
      {
        token: created.ex_token,
        techName: created.ex_tech_name_snapshot,
        createdAt: created.ex_created_at,
      },
      201
    );
  })
);

app.get(
  "/api/exportech/forms/public/:token",
  limiterStrict,
  audit("forms.public_status"),
  asyncH(async (req, res) => {
    const token = String(req.params?.token || "").trim();
    if (!token) return errJson(res, "token obrigatório", 422);

    const form = await ExportechForm.findOne({ ex_token: token }).lean();
    if (!form) return errJson(res, "Token inválido", 404);

    ok(res, {
      token: form.ex_token,
      techName: form.ex_tech_name_snapshot,
      createdAt: form.ex_created_at,
      used: !!form.ex_used_at,
      usedAt: form.ex_used_at,
    });
  })
);

app.post(
  "/api/exportech/submissions/public",
  limiterPublicPost,
  audit("submissions.public_create"),
  asyncH(async (req, res) => {
    const formToken = String(req.body?.formToken || "").trim();
    if (!formToken) return errJson(res, "formToken obrigatório", 422);

    const empresa = safeStr(req.body?.empresa);
    const cliente = safeStr(req.body?.cliente);
    const dataAss = safeStr(req.body?.dataAss);
    const comentario = String(req.body?.comentario || "").trim();

    const r1 = Number(req.body?.r1);
    const r2 = Number(req.body?.r2);
    const r3 = Number(req.body?.r3);
    const r4 = Number(req.body?.r4);
    const r5 = Number(req.body?.r5);

    const npsRaw = req.body?.nps;
    const nps = npsRaw === null || npsRaw === undefined || npsRaw === "" ? null : Number(npsRaw);

    const inRange15 = (n) => Number.isFinite(n) && n >= 1 && n <= 5;
    if (!empresa) return errJson(res, "Empresa obrigatória", 422);
    if (!cliente) return errJson(res, "Cliente obrigatório", 422);
    if (!dataAss) return errJson(res, "Data obrigatória", 422);
    if (![r1, r2, r3, r4, r5].every(inRange15)) return errJson(res, "Ratings inválidos", 422);
    if (nps !== null && !(Number.isFinite(nps) && nps >= 0 && nps <= 10)) return errJson(res, "NPS inválido", 422);

    const sessionDb = await mongoose.startSession();
    try {
      let createdId = null;

      await sessionDb.withTransaction(async () => {
        const form = await ExportechForm.findOne({ ex_token: formToken }).session(sessionDb);
        if (!form) throw Object.assign(new Error("Token inválido"), { code: 404 });
        if (form.ex_used_at) throw Object.assign(new Error("Este formulário já foi submetido."), { code: 409 });

        form.ex_used_at = new Date();
        await form.save({ session: sessionDb });

        const doc = await ExportechSubmission.create(
          [
            {
              ex_tech: form.ex_tech,
              ex_tech_name_snapshot: form.ex_tech_name_snapshot,
              ex_empresa: empresa,
              ex_cliente: cliente,
              ex_data_ass: dataAss,
              ex_r1: r1,
              ex_r2: r2,
              ex_r3: r3,
              ex_r4: r4,
              ex_r5: r5,
              ex_nps: nps,
              ex_comentario: comentario,
            },
          ],
          { session: sessionDb }
        );

        const submission = doc?.[0];
        createdId = submission ? String(submission._id) : null;

        form.ex_used_submission = submission?._id || null;
        await form.save({ session: sessionDb });
      });

      if (!createdId) return errJson(res, "Erro ao criar submissão", 500);
      ok(res, { id: createdId }, 201);
    } catch (e) {
      const code = e?.code || 500;
      if (code === 404) return errJson(res, "Token inválido", 404);
      if (code === 409) return errJson(res, "Este formulário já foi submetido.", 409);
      console.error("public submission tx error:", e && e.stack ? e.stack : e);
      return errJson(res, "Erro ao submeter", 500);
    } finally {
      sessionDb.endSession().catch(() => {});
    }
  })
);

app.get(
  "/api/exportech/submissions",
  limiterStrict,
  requireAuth(["master", "technician"]),
  audit("submissions.list"),
  asyncH(async (req, res) => {
    const u = req.session.user;

    const filter = {};
    if (u.role === "technician") {
      if (!u.technicianId) return errJson(res, "Conta de técnico sem technicianId", 500);
      filter.ex_tech = u.technicianId;
    }

    const docs = await ExportechSubmission.find(filter).sort({ ex_created_at: -1 }).lean();
    const out = docs.map((s) => ({
      id: String(s._id),
      techId: String(s.ex_tech),
      techName: s.ex_tech_name_snapshot,
      empresa: s.ex_empresa,
      cliente: s.ex_cliente,
      dataAss: s.ex_data_ass,
      r1: s.ex_r1,
      r2: s.ex_r2,
      r3: s.ex_r3,
      r4: s.ex_r4,
      r5: s.ex_r5,
      nps: s.ex_nps,
      comentario: s.ex_comentario,
      createdAt: s.ex_created_at,
    }));

    ok(res, out);
  })
);




app.get("/" , (_req, res) => res.json({ ok: true, status:"Nice job !" }));  
app.get("/api/exportech/health", (_req, res) => res.json({ ok: true }));



process.on("unhandledRejection", (reason) => rememberError("process.unhandledRejection", reason));
process.on("uncaughtException", (e) => rememberError("process.uncaughtException", e));

export default app;
