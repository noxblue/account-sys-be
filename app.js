var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
var cors = require("cors");
var session = require("express-session");
require("dotenv").config();

var indexRouter = require("./routes/index");
var userRouter = require("./routes/user");

var app = express();
var devMode = app.get("env") === "development";
var sessionSecret = process.env.SESSION_SECRET;

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// setting cors
var getAllowedOrigins = () => {
  const origins = ["localhost:5173", "127.0.0.1:5173", "10.102.251.37:5173"];
  const httpProtocol = devMode ? "http://" : "https://";
  return origins.map((origin) => `${httpProtocol}${origin}`);
};
var allowedOrigins = getAllowedOrigins();
var corsOptions = {
  origin: function (origin, callback) {
    if (allowedOrigins.indexOf(origin) === -1) {
      callback(new Error("Not allowed by CORS"));
    } else {
      callback(null, true);
    }
  },
  methods: ["GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE"],
  allowedHeaders: [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
  ],
  credentials: true,
};
app.use(cors(corsOptions));

// setting session
var sessionConfig = {
  name: "ssid",
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: devMode ? false : "none",
    secure: !devMode,
    httpOnly: !devMode,
    maxAge: 1000 * 60 * 10,
  },
};
if (!devMode) {
  app.set("trust proxy", 1); // trust first proxy
}
app.use(session(sessionConfig));

// use routers
app.use("/", indexRouter);
app.use("/user", userRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};
  res.status(err.status || 500);
});

module.exports = app;
