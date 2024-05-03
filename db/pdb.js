const { sql } = require("@vercel/postgres");

const createUserTable = async () => {
  const query = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      uid UUID UNIQUE,
      name VARCHAR(255),
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      create_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      update_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`;
  try {
    await sql.query(query);
    console.log("User table created successfully");
  } catch (error) {
    console.log("Error creating user table", error);
  }
};

const pdbCreateUser = async ({ id, name, email, password }) => {
  const query = `
    INSERT INTO users (uid, name, email, password)
    VALUES ('${id}', '${name}', '${email}', '${password}')
    RETURNING *`;
  try {
    const result = await sql.query(query);
    return result.rows[0];
  } catch (error) {
    console.log("Error creating user", error);
    return null;
  }
};

const pdbGetUser = async ({ email, id }) => {
  let query = `SELECT * FROM users WHERE `;
  if (email) {
    query += `email = '${email}'`;
  } else if (id) {
    query += `uid = '${id}'`;
  } else {
    return null;
  }
  try {
    const result = await sql.query(query);
    return result.rows[0];
  } catch (error) {
    console.log("Error getting user", error);
    return null;
  }
};

const pdbUpdateUser = async ({ id, name, email, password }) => {
  let query = `UPDATE users SET `;
  if (name) query += `name = '${name}', `;
  if (email) query += `email = '${email}', `;
  if (password) query += `password = '${password}', `;
  query += `update_time = CURRENT_TIMESTAMP WHERE uid = '${id}' RETURNING *`;
  try {
    const result = await sql.query(query);
    return result.rows[0];
  } catch (error) {
    console.log("Error updating user", error);
    return null;
  }
};

const pdbDeleteUser = async ({ id }) => {
  const query = `DELETE FROM users WHERE uid = '${id}' RETURNING *`;
  try {
    const result = await sql.query(query);
    if (result.rowCount > 0) {
      return { success: true, message: "User deleted successfully" };
    } else {
      return { success: false, message: "User not found" };
    }
  } catch (error) {
    console.log("Error deleting user", error);
    return { success: false, message: "Error deleting user" };
  }
};

module.exports = {
  createUserTable,
  pdbCreateUser,
  pdbGetUser,
  pdbUpdateUser,
  pdbDeleteUser,
};
