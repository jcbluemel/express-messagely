"use strict";

const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");
const { UnauthorizedError } = require("../expressError");

const Router = require("express").Router;
const router = new Router();


/** POST /login: {username, password} => {token}
 *  If not authenticated, throw 401 Error.
 */

router.post("/login", async function (req, res, next) {

  const { username, password } = req.body;

  if (await User.authenticate(username, password)) {

    await User.updateLoginTimestamp(username);
    const token = jwt.sign(username, SECRET_KEY);

    return res.json({ token });
  }
  throw new UnauthorizedError("Invalid user/password");
});

/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */

router.post("/register", async function (req, res, next) {

  const { username, password, first_name, last_name, phone } = req.body;

  const user = await User.register(
    username, password, first_name, last_name, phone);

  await User.updateLoginTimestamp(username);
  const token = jwt.sign(username, SECRET_KEY);

  return res.json({ token });
});


module.exports = router;