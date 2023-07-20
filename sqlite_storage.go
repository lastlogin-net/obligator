package main

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/mattn/go-sqlite3"
)

type SqliteStorage struct {
	db *sql.DB
}

func NewSqliteStorage(path string) (*SqliteStorage, error) {

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	stmt := `
        create table users (id integer not null primary key, email text);
        `
	_, err = db.Exec(stmt)
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		if sqliteErr.Code != sqlite3.ErrError {
			return nil, err
		}
	}

	stmt = `
        create table root_uri (id integer not null primary key, root_uri text);
        `
	_, err = db.Exec(stmt)
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		if sqliteErr.Code != sqlite3.ErrError {
			return nil, err
		}
	}

	stmt = `
        insert into root_uri values(0, "");
        `
	_, err = db.Exec(stmt)
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		if sqliteErr.Code != sqlite3.ErrConstraint {
			return nil, err
		}
	}

	s := &SqliteStorage{
		db: db,
	}

	return s, nil
}

func (s *SqliteStorage) GetRootUri() string {
	var rootUri string
	err := s.db.QueryRow("select root_uri from root_uri where id=0").Scan(&rootUri)
	// TODO: handle errors
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return rootUri
}

func (s *SqliteStorage) SetRootUri(rootUri string) error {
	stmt := `
        update root_uri set root_uri = ?;
        `
	_, err := s.db.Exec(stmt, rootUri)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	return nil
}
