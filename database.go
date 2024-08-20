package obligator

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"
)

type DatabaseIface interface {
	GetConfig() (*DbConfig, error)
	GetJwksJson() (string, error)
}

type User struct {
	IdType string `json:"id_type" db:"id_type"`
	Id     string `json:"email" db:"id"`
}

type DbConfig struct {
	Public bool `json:"public"`
}

type Database struct {
	db     *sqlx.DB
	prefix string
}

func NewDatabase(path string, prefix string) (*Database, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	return NewDatabaseWithDb(db, prefix)
}

func NewDatabaseWithDb(sqlDb *sql.DB, prefix string) (*Database, error) {

	db := sqlx.NewDb(sqlDb, "sqlite3")

	stmt := fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %sconfig(
                jwks_json TEXT UNIQUE DEFAULT "" NOT NULL,
                public BOOLEAN UNIQUE DEFAULT false NOT NULL
        );
        `, prefix)
	_, err := db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	stmt = fmt.Sprintf(`
        SELECT COUNT(*) FROM %sconfig;
        `, prefix)
	var numRows int
	err = db.QueryRow(stmt).Scan(&numRows)
	if err != nil {
		return nil, err
	}

	if numRows == 0 {
		stmt = fmt.Sprintf(`
                INSERT INTO %sconfig DEFAULT VALUES;
                `, prefix)
		_, err = db.Exec(stmt)
		if err != nil {
			return nil, err
		}
	}

	stmt = fmt.Sprintf(`
        create table %semail_validation_requests(id integer not null primary key, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, hashed_requester_id TEXT NOT NULL, hashed_email TEXT NOT NULL);
        `, prefix)
	_, err = db.Exec(stmt)
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		if sqliteErr.Code != sqlite3.ErrError {
			return nil, err
		}
	}

	stmt = fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %sdomains(
                domain TEXT UNIQUE,
                hashed_owner_id TEXT
        );
        `, prefix)
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	stmt = fmt.Sprintf(`
        CREATE TABLE IF NOT EXISTS %susers(
                id TEXT PRIMARY KEY,
                id_type TEXT
        );
        `, prefix)
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	s := &Database{
		db:     db,
		prefix: prefix,
	}

	return s, nil
}

func (s *Database) GetConfig() (*DbConfig, error) {
	var c DbConfig

	stmt := fmt.Sprintf("SELECT public FROM %sconfig", s.prefix)
	err := s.db.QueryRow(stmt).Scan(&c.Public)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

func (d *Database) GetJwksJson() (string, error) {
	var jwksJson string

	stmt := fmt.Sprintf(`
        SELECT jwks_json FROM %sconfig;
        `, d.prefix)
	err := d.db.QueryRow(stmt).Scan(&jwksJson)
	if err != nil {
		return "", err
	}

	return jwksJson, nil
}

func (d *Database) SetJwksJson(jwksJson string) error {

	stmt := fmt.Sprintf(`
        UPDATE %sconfig SET jwks_json=?;
        `, d.prefix)
	_, err := d.db.Exec(stmt, jwksJson)
	if err != nil {
		return err
	}

	return nil
}

func (s *Database) SetPublic(public bool) error {
	stmt := fmt.Sprintf(`
        UPDATE %sconfig SET public=?;
        `, s.prefix)
	_, err := s.db.Exec(stmt, public)
	if err != nil {
		return err
	}

	return nil
}

func (s *Database) AddEmailValidationRequest(requesterId, email string) error {
	stmt := fmt.Sprintf(`
        INSERT INTO %semail_validation_requests(hashed_requester_id,hashed_email) VALUES(?,?);
        `, s.prefix)
	_, err := s.db.Exec(stmt, Hash(requesterId), Hash(email))
	if err != nil {
		return err
	}
	return nil
}

type EmailValidationCount struct {
	HashedRequesterId string
	Count             int
}

func (s *Database) GetEmailValidationCounts(since time.Time) ([]*EmailValidationCount, error) {

	timeFmt := since.Format(time.DateTime)
	stmt := fmt.Sprintf(`
        SELECT hashed_requester_id,count(*) FROM %semail_validation_requests WHERE timestamp > ? GROUP BY hashed_requester_id
        `, s.prefix)
	rows, err := s.db.Query(stmt, timeFmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := []*EmailValidationCount{}

	for rows.Next() {
		var count EmailValidationCount
		err = rows.Scan(&count.HashedRequesterId, &count.Count)
		if err != nil {
			return nil, err
		}
		counts = append(counts, &count)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return counts, nil
}

func (s *Database) AddDomain(domain, ownerId string) error {
	stmt := fmt.Sprintf(`
        INSERT INTO %sdomains(domain,hashed_owner_id) VALUES(?,?);
        `, s.prefix)
	_, err := s.db.Exec(stmt, domain, Hash(ownerId))
	if err != nil {
		return err
	}
	return nil
}

type Domain struct {
	HashedOwnerId string
	Domain        string
}

func (s *Database) GetDomain(domain string) (*Domain, error) {

	var d Domain

	stmt := fmt.Sprintf("SELECT domain,hashed_owner_id FROM %sdomains WHERE domain = ?", s.prefix)
	err := s.db.QueryRow(stmt, domain).Scan(&d.Domain, &d.HashedOwnerId)
	if err != nil {
		return nil, err
	}

	return &d, nil
}

func (s *Database) GetDomains() ([]*Domain, error) {

	rows, err := s.db.Query(fmt.Sprintf("SELECT * FROM %sdomains", s.prefix))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	allDomains := []*Domain{}

	for rows.Next() {
		var d Domain
		err = rows.Scan(&d.Domain, &d.HashedOwnerId)
		if err != nil {
			return nil, err
		}
		allDomains = append(allDomains, &d)
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return allDomains, nil
}

func (d *Database) GetUsers() ([]*User, error) {

	stmt := fmt.Sprintf(`
        SELECT * FROM %susers;
        `, d.prefix)

	var users []*User

	err := d.db.Select(&users, stmt)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (d *Database) SetUser(u *User) error {
	stmt := fmt.Sprintf(`
        INSERT OR REPLACE INTO %susers(id_type,id) VALUES(?,?);
        `, d.prefix)
	_, err := d.db.Exec(stmt, u.IdType, u.Id)
	if err != nil {
		return err
	}

	return nil
}
