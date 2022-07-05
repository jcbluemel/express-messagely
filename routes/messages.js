"use strict";

const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");
const Message = require("../models/message");
const { UnauthorizedError } = require("../expressError");

const Router = require("express").Router;
const router = new Router();

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Makes sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get("/:id", ensureLoggedIn, async function (req, res) {
  const id = req.params.id;
  const message = await Message.get(id);

  if (!(res.locals.user.username === message.from_user.username) ||
    !(res.locals.user.username === message.to_user.username)) {
    throw new UnauthorizedError("You do not have permission to view this message.");
  }

  return res.json({ message });
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 * makes sure that the currently logged in user is trying to send message
 *
 **/
router.post("/", ensureCorrectUser, async function (req, res) {
  const from_username = res.locals.user.username;
  const { to_username, body } = req.body;
  console.log("from_username", from_username);
  const message = await Message.create({ from_username, to_username, body });
  return res.json({ message });

});


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Makes sure that the only the intended recipient can mark as read.
 *
 **/


module.exports = router;