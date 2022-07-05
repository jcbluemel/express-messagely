"use strict";

const { ensureLoggedIn } = require("../middleware/auth");
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
  const msg = await Message.get(id);

  if (!(res.locals.user.username === msg.from_user.username) ||
      !(res.locals.user.username === msg.to_user.username)) {
      throw new UnauthorizedError("You do not have permission to view this message.");
  }

  return res.json({ msg });
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Makes sure that the only the intended recipient can mark as read.
 *
 **/


module.exports = router;