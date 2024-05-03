var express = require("express");
var router = express.Router();
var jwt = require("jsonwebtoken");
var bcrypt = require("bcrypt");
var { v4: uuidv4 } = require("uuid");
var { pdbCreateUser, pdbGetUser, pdbUpdateUser } = require("../db/pdb");
require("dotenv").config();

var jwtLoginSecret = process.env.LOGIN_JWT_SECRET;
var jwtRegisterSecret = process.env.REGIST_JWT_SECRET;

// 登入
router.post("/login", async function (req, res, next) {
  // 從req取得帳號密碼
  // 使用帳號向資料庫取得資料，資料為空返回401
  // 將密碼與資料中hashed密碼比對，比對不符，返回401
  // 比對正確，將使用者id,email,與現在時間+8小時的timestamp製作成JWT的token設定至cookie中
  // 於data中提供id,email，存入session.user中，並進行返回200
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  const { email, password } = req.body;
  const user = await pdbGetUser({ email });
  if (!user) {
    resJson.statusCode = "401";
    resJson.message = "用戶不存在";
    return res.status(401).json(resJson);
  }
  if (!bcrypt.compare(password, user.password)) {
    resJson.statusCode = "401";
    resJson.message = "登入錯誤";
    return res.status(401).json(resJson);
  }
  const userData = {
    id: user.uid,
    email: user.email,
  };
  const tokenPayload = {
    ...userData,
    expired: new Date(Date.now() + 600000).getTime(),
  };
  const token = jwt.sign(tokenPayload, jwtLoginSecret);
  const cookieConfig =
    req.app.get("env") === "development"
      ? {}
      : { httpOnly: true, sameSite: "None", secure: true };

  // set session
  req.session.user = { ...userData };
  resJson.data = { ...userData };

  res
    .status(200)
    .cookie("ult", token, {
      expires: new Date(tokenPayload.expired),
      ...cookieConfig,
    })
    .json(resJson);
});

// 註冊
router.post("/signup", async function (req, res, next) {
  // 帳號重複，返回401
  // 資料正確，建立id並將帳號與hasded密碼存入session
  // 隨機生成4碼數字轉為字串，將此字串、帳號、現在時間+5分鐘timestamp製作為JWT
  // 返回200 & JWT token
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  const { email, password } = req.body;
  const isExist = await pdbGetUser({ email });
  if (isExist) {
    resJson.statusCode = "401";
    resJson.message = "帳號已存在";
    return res.status(401).json(resJson);
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const registingAccount = {
    id: uuidv4(),
    email,
    password: hashedPassword,
  };
  const generateVerifyCode = () => {
    const num = Math.floor(Math.random() * 1000);
    return num < 1000 ? `0${num}` : String(num);
  };
  const tokenPayload = {
    code: generateVerifyCode(),
    user: { id: registingAccount.id, email: registingAccount.email },
    expired: new Date(Date.now() + 300000),
  };
  const registToken = jwt.sign(tokenPayload, jwtRegisterSecret);
  resJson.data = {
    verifyCode: tokenPayload.code,
    verifyKey: registToken,
  };
  req.session.registingAccount = { ...registingAccount };
  res.status(200).json(resJson);
});

// 驗證註冊
router.patch("/verify", async function (req, res, next) {
  // JWT解析失敗返回401
  // JWT解析成功，時間過期，返回401
  // code 與 JWT內不符返回401
  // 檢查與session帳號是否相同，不同返回401
  // 將session資料中id,帳號,hashed密碼存入資料庫
  // 移除session中的hashed密碼
  // 返回201
  const resJson = {
    statusCode: "201",
    message: "OK",
    meta: {},
    data: {},
  };
  const { verifyCode, verifyKey } = req.body;
  if (!verifyCode || !verifyKey) {
    resJson.statusCode = "401";
    resJson.message = "ERROR";
    return res.status(401).json(resJson);
  }
  jwt.verify(verifyKey, jwtRegisterSecret, async (err, registData) => {
    if (err) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    if (new Date() > new Date(registData.expired)) {
      resJson.statusCode = "401";
      resJson.message = "驗證碼已過期";
      return res.status(401).json(resJson);
    }
    if (verifyCode !== registData.code) {
      resJson.statusCode = "401";
      resJson.message = "驗證碼錯誤";
      return res.status(401).json(resJson);
    }
    const registingAccount = { ...req.session.registingAccount };
    if (!registingAccount || registData.user?.id !== registingAccount.id) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    // 將registingAccount存入資料庫
    const result = await pdbCreateUser({
      id: registingAccount.id,
      email: registingAccount.email,
      password: registingAccount.password,
    });
    if (!result) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    resJson.data = { id: registingAccount.id, email: registingAccount.email };
    delete req.session.registingAccount;
    res.status(201).json(resJson);
  });
});

// 以下api皆需登入狀態

// 登入狀態檢查
router.put("/auth-valid", function (req, res, next) {
  // 從req的cookie中取得JWT
  // 解析失敗返回400
  // JWT解析成功，時間過期，返回401
  // 距離過期時間小於週期的一半，更新JWT，更新cookie
  // 返回200
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  const loginToken = req.cookies.ult;
  if (!loginToken) {
    resJson.statusCode = "401";
    resJson.message = "ERROR";
    return res.status(401).json(resJson);
  }
  jwt.verify(loginToken, jwtLoginSecret, (err, user) => {
    if (err) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    if (new Date() > new Date(user.expired)) {
      resJson.statusCode = "401";
      resJson.message = "登入已過期";
      return res.status(401).json(resJson);
    }
    // 距離過期時間小於一半週期，更新token與cookie
    if (
      new Date(user.expired).getTime() - new Date(Date.now()).getTime() <
      300000
    ) {
      const { id, email } = user;
      const tokenPayload = {
        id,
        email,
        expired: new Date(Date.now() + 600000).getTime(),
      };
      const token = jwt.sign(tokenPayload, jwtLoginSecret);
      const cookieConfig =
        req.app.get("env") === "development"
          ? {}
          : { httpOnly: true, sameSite: "None", secure: true };
      return res
        .status(200)
        .cookie("ult", token, {
          expires: new Date(tokenPayload.expired),
          ...cookieConfig,
        })
        .json(resJson);
    }
    return res.status(200).json(resJson);
  });
});

// 取得user資料
router.get("/", function (req, res, next) {
  // 從req的cookie中取得JWT
  // 解析失敗返回401
  // JWT解析成功，時間過期，返回401
  // 從資料庫取得user資料，取得失敗返回404
  // 返回200，{id,email}
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  const loginToken = req.cookies.ult;
  if (!loginToken) {
    resJson.statusCode = "401";
    resJson.message = "ERROR";
    return res.status(401).json(resJson);
  }
  jwt.verify(loginToken, jwtLoginSecret, async (err, user) => {
    if (err) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    if (new Date() > new Date(user.expired)) {
      resJson.statusCode = "401";
      resJson.message = "登入已過期";
      return res.status(401).json(resJson);
    }
    const userData = await pdbGetUser({ id: user.id });
    if (!userData) {
      resJson.statusCode = "404";
      resJson.message = "ERROR";
      return res.status(404).json(resJson);
    }
    const { uid: id, email } = userData;
    req.session.userData = { id, email };
    resJson.data = { ...userData };
    return res.status(200).json(resJson);
  });
});

// 登出
router.delete("/logout", function (req, res, next) {
  // 刪除JWT cookie、刪除session、刪除session的cookie、返回200
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  req.session.destroy();
  res
    .status(200)
    .clearCookie("ult", { httpOnly: true, sameSite: "None", secure: true })
    .clearCookie("ssid", { httpOnly: true, sameSite: "None", secure: true })
    .json(resJson);
});

// 重設密碼
router.patch("/reset-password", async function (req, res, next) {
  // 從req的cookie中取得JWT
  // 解析失敗返回400
  // JWT解析成功，時間過期，返回401
  // 生成隨機6碼數字，hashed存入資料庫
  // 返回200，將密碼一併返回
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  const { email } = req.body;
  const userData = await pdbGetUser({ email });
  if (!userData) {
    resJson.statusCode = "404";
    resJson.message = "ERROR";
    return res.status(404).json(resJson);
  }
  const newPassword = Array(8 + 1)
    .join((Math.random().toString(36) + "00000000000000000").slice(2, 18))
    .slice(0, 8);

  // 將hashedPassword存入資料庫
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  const result = await pdbUpdateUser({
    id: userData.uid,
    password: hashedPassword,
  });
  if (!result) {
    resJson.statusCode = "401";
    resJson.message = "ERROR";
    return res.status(401).json(resJson);
  }

  resJson.data = { code: newPassword };
  return res.status(200).json(resJson);
});

// 更改密碼
router.patch("/change-password", function (req, res, next) {
  // 從req的cookie中取得JWT
  // 解析失敗返回400
  // JWT解析成功，時間過期，返回401
  // 從req的body取得password
  // 將密碼hashed存入資料庫
  // 返回200
  const resJson = {
    statusCode: "200",
    message: "OK",
    meta: {},
    data: {},
  };
  const loginToken = req.cookies.ult;
  if (!loginToken) {
    resJson.statusCode = "401";
    resJson.message = "ERROR";
    return res.status(401).json(resJson);
  }
  jwt.verify(loginToken, jwtLoginSecret, async (err, user) => {
    if (err) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    if (new Date() > new Date(user.expired)) {
      resJson.statusCode = "401";
      resJson.message = "登入已過期";
      return res.status(401).json(resJson);
    }
    const userData = await pdbGetUser({ id: user.id });
    if (!userData) {
      resJson.statusCode = "404";
      resJson.message = "ERROR";
      return res.status(404).json(resJson);
    }
    const { password: newPassword } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    // 將hashedPassword存入資料庫
    const result = await pdbUpdateUser({
      id: user.id,
      password: hashedPassword,
    });
    if (!result) {
      resJson.statusCode = "401";
      resJson.message = "ERROR";
      return res.status(401).json(resJson);
    }
    return res.status(200).json(resJson);
  });
});

module.exports = router;
