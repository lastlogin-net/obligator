package obligator

import (
	"github.com/jmoiron/sqlx"
	"github.com/mattn/go-sqlite3"
	"time"
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
        create table email_validation_requests(id integer not null primary key, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, hashed_requester_id TEXT NOT NULL, hashed_email TEXT NOT NULL);
        `
	_, err = db.Exec(stmt)
	if sqliteErr, ok := err.(sqlite3.Error); ok {
		if sqliteErr.Code != sqlite3.ErrError {
			return nil, err
		}
	}

	stmt = `
        CREATE TABLE IF NOT EXISTS domains(
                domain TEXT UNIQUE,
                hashed_owner_id TEXT
        );
        `
	_, err = db.Exec(stmt)
	if err != nil {
		return nil, err
	}

	s := &Database{
		db: db,
	}

	return s, nil
}

func (s *Database) AddEmailValidationRequest(requesterId, email string) error {
	stmt := `
        INSERT INTO email_validation_requests(hashed_requester_id,hashed_email) VALUES(?,?);
        `
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
	rows, err := s.db.Query("SELECT hashed_requester_id,count(*) FROM email_validation_requests WHERE timestamp > ? GROUP BY hashed_requester_id", timeFmt)
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
	stmt := `
        INSERT INTO domains(domain,hashed_owner_id) VALUES(?,?);
        `
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

	stmt := "SELECT domain,hashed_owner_id FROM domains WHERE domain = ?"
	err := s.db.QueryRow(stmt, domain).Scan(&d.Domain, &d.HashedOwnerId)
	if err != nil {
		return nil, err
	}

	return &d, nil
}

func (s *Database) GetDomains() ([]*Domain, error) {

	rows, err := s.db.Query("SELECT * FROM domains")
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
