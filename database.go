package main

import (
	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sqlx.DB
}

func NewDatabase(path string) (*Database, error) {

	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	stmt := `
        create table email_validation_requests(id integer not null primary key, hashed_requester_email TEXT NOT NULL, hashed_validation_email TEXT NOT NULL);
        `
	_, err = db.Exec(stmt)
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		if sqliteErr.Code != sqlite3.ErrError {
			return nil, err
		}
	}

	s := &Database{
		db: db,
	}

	return s, nil
}
