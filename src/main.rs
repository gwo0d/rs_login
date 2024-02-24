use sha3::{Digest, Sha3_512};
use rusqlite::{Connection};
use rand::{random};
use hex::encode;

struct User {
    username: String,
    password_hash: String,
    salt: String
}

fn create_user(db: &Connection, username: &str, password: &str) -> bool {
    let salt = encode(random::<[u8; 16]>());
    let mut hasher = Sha3_512::new();
    hasher.update(password);
    hasher.update(&salt);
    let password_hash = hasher.finalize();

    let user = User {
        username: username.parse().unwrap(),
        password_hash: encode(password_hash),
        salt
    };

    let exists = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1)",
        &[&user.username],
        |row| {
            Ok(row.get(0)?)
        }
    ).unwrap();

    if exists {
        return false;
    }

    db.execute(
        "INSERT INTO users (username, password_hash, salt) VALUES (?1, ?2, ?3)",
        &[&user.username, &user.password_hash, &user.salt],
    ).unwrap();

    true
}

fn authenticate_user(db: &Connection, username: &str, password: &str) -> bool {
    let user = db.query_row(
        "SELECT id, username, password_hash, salt FROM users WHERE username = ?1",
        &[&username],
        |row| {
            Ok(User {
                username: row.get(1)?,
                password_hash: row.get(2)?,
                salt: row.get(3)?
            })
        }
    ).unwrap(); // TODO: Handle error on unrecognised username

    let mut hasher = Sha3_512::new();
    hasher.update(password);
    hasher.update(user.salt);
    let password_hash = hasher.finalize();

    if encode(password_hash) == user.password_hash {
        true
    }
    else {
        false
    }
}

fn main() {
    let db = Connection::open("users.db").unwrap();

    db.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )",
        [],
    ).unwrap();

    let menu_options = vec!["Create user", "Login", "Delete User", "Exit"];

    loop {
        for (i, option) in menu_options.iter().enumerate() {
            println!("{}. {}", i + 1, option);
        }

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();

        match input {
            "1" => {
                println!("Enter username:");
                let mut username = String::new();
                std::io::stdin().read_line(&mut username).unwrap();
                let username = username.trim();

                println!("Enter password:");
                let mut password = String::new();
                std::io::stdin().read_line(&mut password).unwrap();
                let password = password.trim();

                let result = create_user(&db, username, password);

                if result {
                    println!("User created");
                }
                else {
                    println!("Username already exists");
                }
            },

            "2" => {
                println!("Enter username:");
                let mut username = String::new();
                std::io::stdin().read_line(&mut username).unwrap();
                let username = username.trim();

                println!("Enter password:");
                let mut password = String::new();
                std::io::stdin().read_line(&mut password).unwrap();
                let password = password.trim();

                let result = authenticate_user(&db, username, password);

                if result {
                    println!("Login successful");
                }
                else {
                    println!("Login failed");
                }
            }

            "3" => {
                println!("Enter username:");
                let mut username = String::new();
                std::io::stdin().read_line(&mut username).unwrap();
                let username = username.trim();

                println!("Enter password:");
                let mut password = String::new();
                std::io::stdin().read_line(&mut password).unwrap();
                let password = password.trim();

                let authenticated = authenticate_user(&db, username, password);

                if authenticated {
                    db.execute(
                        "DELETE FROM users WHERE username = ?1",
                        &[&username],
                    ).unwrap();
                    println!("User deleted");
                }
                else {
                    println!("Login failed");
                }
            }

            "4" => {
                break;
            }

            _ => {
                eprintln!("Invalid input");
            }
        }
    }
}