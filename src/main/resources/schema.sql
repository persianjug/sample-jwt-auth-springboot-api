DROP TABLE IF EXISTS accounts;

CREATE TABLE
  accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(250) NOT NULL UNIQUE,
    password VARCHAR(250) NOT NULL
  );


DROP TABLE IF EXISTS refreshtoken;

CREATE TABLE
  refreshtoken (
    id INT PRIMARY KEY AUTO_INCREMENT,
    account_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expiry_date DATETIME NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts (id)
  );