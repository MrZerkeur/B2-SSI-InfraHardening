CREATE DATABASE IF NOT EXISTS website;

USE website;

CREATE TABLE users (
    user_id INT(11) NOT NULL AUTO_INCREMENT,
    hashed_password VARCHAR(100) NOT NULL,
    salt VARCHAR(100) NOT NULL,
    is_admin TINYINT(1) NULL,
    username VARCHAR(24) NOT NULL,
    PRIMARY KEY (user_id),
    UNIQUE (username)
);

CREATE TABLE contact_forms (
    id INT NOT NULL AUTO_INCREMENT,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    tel VARCHAR(20) NOT NULL,
    file_path VARCHAR(255),
    message VARCHAR(300) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO users (hashed_password, salt, is_admin, username)
VALUES (
    '$2a$10$V0MGfWeg9aq1yCJV/cxQH.gKbhTJEGDBKd653qGr3b8zevszlqzoi',
    '$2a$10$V0MGfWeg9aq1yCJV/cxQH.',
    1,
    'LAdminTroSympaLeMeilleur'
);