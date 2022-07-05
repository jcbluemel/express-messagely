"use strict";

const db = require("../db");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");
const { NotFoundError, BadRequestError } = require("../expressError");


/** User of the site. */

class User {

  /** Register new user. Returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {

    const hashedPassword = await bcrypt.hash(
      password, BCRYPT_WORK_FACTOR);

    try {
      const result = await db.query(
        `INSERT INTO users
            (username, password, first_name, last_name, phone, join_at)
          VALUES
            ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
          RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone]
      );
    } catch (err) {
      throw new BadRequestError("Username taken");
    }

    return result.rows[0];
  }

  /** Authenticate: is username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password
         FROM users
         WHERE username = $1`,
      [username]);
    const user = result.rows[0];

    if (user) {
      if (await bcrypt.compare(password, user.password) === true) {
        return true;
      }
    }
    return false;
  }

  /** Update last_login_at for user
   * throws error is no user found
   */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
        SET last_login_at = CURRENT_TIMESTAMP
        WHERE username = $1
        RETURNING username`,
      [username]
    );

    if (!result.rows[0]) throw new NotFoundError(`No such user: ${username}`);
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name
      FROM users
      ORDER BY username`
    );

    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at }
   *
   * If no user throws error*/

  static async get(username) {

    const result = await db.query(
      `SELECT username,
              first_name,
              last_name,
              phone,
              join_at,
              last_login_at
         FROM users
         WHERE username = $1`,
      [username]);

    let user = result.rows[0];
    if (!user) {
      throw new NotFoundError(`No such username: ${username}`);
    }

    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   *
   * If messages can't be found throws error
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT m.id,
              m.to_username as to_user,
              m.body,
              m.sent_at,
              m.read_at,
              t.first_name,
              t.last_name,
              t.phone
      FROM messages as m
              JOIN users AS t ON m.to_username = t.username
      WHERE from_username = $1
      ORDER BY m.sent_at DESC`,
      [username]
    );
    const ms = results.rows;

    if (ms.length === 0) {
      return ms;
    };

    return ms.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_user,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }


  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   *
   * If messages can't be found throws error
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT m.id,
              m.from_username as from_user,
              m.body,
              m.sent_at,
              m.read_at,
              f.first_name,
              f.last_name,
              f.phone
      FROM messages as m
              JOIN users AS f ON m.from_username = f.username
      WHERE to_username = $1
      ORDER BY m.sent_at DESC`,
      [username]
    );
    const ms = results.rows;

    if (ms.length === 0) {
      return ms;
    };

    return ms.map(m => m = {
      id: m.id,
      from_user: {
        username: m.from_user,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    });
  }
}


module.exports = User;
